package nl.sanderdijkhuis.macaroons

import cats.data._
import cats.effect._
import cats.implicits._
import eu.timepit.refined.refineV
import fs2.Stream
import scodec.bits.ByteVector
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XChaCha20Poly1305}
import tsec.cipher.symmetric.{
  AuthCipherAPI,
  AuthEncryptor,
  CipherText,
  Iv,
  IvGen,
  PlainText,
  RawCipherText
}
import tsec.hashing.{CryptoHashAPI, CryptoHasher}
import tsec.hashing.jca.SHA256
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.MessageAuth
import tsec.mac.jca.{HMACSHA256, MacSigningKey}
import eu.timepit.refined._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.numeric._
import eu.timepit.refined.api.{RefType, Refined}
import eu.timepit.refined.boolean._
import eu.timepit.refined.char._
import eu.timepit.refined.collection._
import eu.timepit.refined.generic._
import eu.timepit.refined.string._
import eu.timepit.refined.scodec.byteVector._

import javax.crypto.spec.SecretKeySpec

trait MacaroonService[F[_]] {

  def generate(identifier: Identifier,
               rootKey: RootKey,
               maybeLocation: Option[Location]): F[Macaroon with Authority]

  def bind(authorizing: Macaroon with Authority,
           discharging: Macaroon): F[Macaroon]

  def addFirstPartyCaveat(macaroon: Macaroon with Authority,
                          identifier: Identifier): F[Macaroon with Authority]

  def addThirdPartyCaveat(
      macaroon: Macaroon with Authority,
      key: RootKey,
      identifier: Identifier,
      maybeLocation: Option[Location]): F[Macaroon with Authority]

  def verify(macaroon: Macaroon with Authority,
             key: RootKey,
             verifier: Verifier,
             Ms: Set[Macaroon]): F[VerificationResult]
}

object MacaroonService {

  trait TsecLive[
      F[_], HashAlgorithm, HmacAlgorithm, AuthCipher, AuthCipherSecretKey[_]]
      extends MacaroonService[F] {

    implicit val sync: Sync[F]
    implicit val hasher: CryptoHasher[F, HashAlgorithm]
    implicit val mac: MessageAuth[F, HmacAlgorithm, MacSigningKey]
    implicit val counterStrategy: IvGen[F, AuthCipher]
    implicit val encryptor: AuthEncryptor[F, AuthCipher, AuthCipherSecretKey]
    implicit val authCipherAPI: AuthCipherAPI[AuthCipher, AuthCipherSecretKey]
    implicit val keyGen: SymmetricKeyGen[F, AuthCipher, AuthCipherSecretKey]

    private def nonEmptyByteVector(
        byteVector: ByteVector): F[NonEmptyByteVector] = {
      val x: Either[String, NonEmptyByteVector] = refineV(byteVector)
      Sync[F].fromEither(x.leftMap(new Exception(_)))
    }

    private def hash(byteVector: ByteVector): F[NonEmptyByteVector] = {
      for {
        a <- hasher.hash(byteVector.toArray).map(ByteVector.apply)
        b <- nonEmptyByteVector(a)
      } yield b
//      val result: Either[String, NonEmptyByteVector] = refineV(
//        hasher.hash(byteVector.toArray))
//      Sync[F].fromEither(result.leftMap(new Exception(_)))
    }

    private def bind(authorizing: Macaroon with Authority,
                     dischargingTag: AuthenticationTag): F[AuthenticationTag] =
      hash(dischargingTag.value ++ authorizing.tag.value)
        .map(AuthenticationTag.apply)

    //      hash(dischargingTag ++ authorizing.tag).map(AuthenticationTag.apply)

    def bind(authorizing: Macaroon with Authority,
             discharging: Macaroon): F[Macaroon] =
      bind(authorizing, discharging.tag).map(t => discharging.copy(tag = t))

    private def toKey(byteVector: ByteVector): MacSigningKey[HmacAlgorithm] =
      MacSigningKey(new SecretKeySpec(byteVector.toArray, mac.algorithm))

//    private def authenticateHelper(data: ByteVector,
//                                   key: MacSigningKey[HmacAlgorithm]):F[AuthenticationTag] =

    private def authenticate(
        data: ByteVector,
        key: MacSigningKey[HmacAlgorithm]): F[AuthenticationTag] =
      mac
        .sign(data.toArray, key)
        .map(ByteVector(_))
        .flatMap(nonEmptyByteVector)
        .map(AuthenticationTag.apply)

    private def authenticateCaveat(
        tag: AuthenticationTag,
        maybeChallenge: Option[Challenge],
        identifier: Identifier): F[AuthenticationTag] = {
      val data = maybeChallenge.fold(ByteVector.empty)(_.value) ++ identifier.value
      authenticate(data, toKey(tag.value))
    }

    private def addCaveatHelper(
        macaroon: Macaroon with Authority,
        identifier: Identifier,
        maybeVerificationKeyId: Option[Challenge],
        maybeLocation: Option[Location]): F[Macaroon with Authority] = {
      val caveats = macaroon.caveats :+ Caveat(maybeLocation,
                                               identifier,
                                               maybeVerificationKeyId)
      authenticateCaveat(macaroon.tag, maybeVerificationKeyId, identifier)
        .map(tag => macaroon.copy(caveats = caveats, tag = tag))
        .map(_.asInstanceOf[Macaroon with Authority])
    }

    def generate(identifier: Identifier,
                 rootKey: RootKey,
                 maybeLocation: Option[Location]): F[Macaroon with Authority] =
      authenticate(identifier.value, toKey(rootKey.value)).map(
        tag =>
          Macaroon(maybeLocation, identifier, Vector.empty, tag)
            .asInstanceOf[Macaroon with Authority])

    def addFirstPartyCaveat(
        macaroon: Macaroon with Authority,
        identifier: Identifier): F[Macaroon with Authority] =
      addCaveatHelper(macaroon, identifier, None, None)

    def addThirdPartyCaveat(
        macaroon: Macaroon with Authority,
        key: RootKey,
        identifier: Identifier,
        maybeLocation: Option[Location]): F[Macaroon with Authority] =
      for {
        k <- keyGen.build(macaroon.tag.value.toArray)
        t = PlainText(key.value.toArray)
        e <- authCipherAPI.encrypt[F](t, k)
        c <- Sync[F]
          .fromEither(
            refineV[NonEmpty](ByteVector(e.toConcatenated))
              .leftMap(new Throwable(_)))
          .map(Challenge.apply)
        m <- addCaveatHelper(macaroon, identifier, Some(c), maybeLocation)
      } yield m

    def decrypt(tag: AuthenticationTag, challenge: Challenge): F[RootKey] =
      for {
        k <- keyGen.build(tag.value.toArray)
        (content, nonce) = challenge.value.splitAt(challenge.value.length - 24) // TODO
        c = CipherText[AuthCipher](RawCipherText(content.toArray),
                                   Iv(nonce.toArray))
        d <- authCipherAPI.decrypt(c, k)
        key <- Sync[F].fromEither(
          refineV[NonEmpty](ByteVector(d)).leftMap(new Throwable(_)))
      } yield RootKey(key)

    def verify(macaroon: Macaroon with Authority,
               key: RootKey,
               verifier: Verifier,
               macaroons: Set[Macaroon]): F[VerificationResult] = {
      val Ms = Stream.emits[F, Macaroon](macaroons.toSeq)

      def helper(discharge: Option[Macaroon], k: RootKey): F[Boolean] = {
        val M = discharge.getOrElse(macaroon)
        val caveats = Stream.emits[F, Caveat](M.caveats)
        val signatures = Stream
          .eval(authenticate(M.identifier.value, toKey(k.value)))
          .flatMap(cSig =>
            caveats.evalScan(cSig)((cSig, c) =>
              authenticateCaveat(cSig, c.maybeChallenge, c.identifier)))
        val verifications = caveats.zip(signatures).flatMap {
          case (Caveat(_, cId, None), _) => Stream.emit(verifier(cId))
          case (Caveat(_, cId, Some(vId)), cSig) =>
            Stream
              .eval(decrypt(cSig, vId))
              .flatMap(
                key =>
                  Ms.filter(_.identifier == cId)
                    .evalMap(m => helper(Some(m), key))
                    .find(_ == true)
                    .lastOr(false))
        }
        val allCaveatsAreVerified =
          verifications.forall(_ == true).compile.last.map(_.isDefined)
        val tagValidates = OptionT(signatures.compile.last)
          .semiflatMap(last =>
            discharge.fold(last.pure[F])(_ => bind(macaroon, last)))
          .map(_ == M.tag)
          .getOrElse(false)
        allCaveatsAreVerified.flatMap(a => tagValidates.map(b => a && b))
      }

      helper(None, key).map(b => if (b) Verified else VerificationFailed)
    }
  }

  class Live[F[_]]()(
      implicit override val sync: Sync[F],
//      override val hasher: CryptoHasher[F, SHA256],
//      override val mac: MessageAuth[F, HMACSHA256, MacSigningKey],
//      override val counterStrategy: IvGen[F, XChaCha20Poly1305],
//      override val encryptor: AuthEncryptor[F,
//                                            XChaCha20Poly1305,
//                                            BouncySecretKey],
//      override val authCipherAPI: AuthCipherAPI[XChaCha20Poly1305,
//                                                BouncySecretKey],
//                     override val keyGen: SymmetricKeyGen[F,
//                                                          XChaCha20Poly1305,
//                                                          BouncySecretKey]
  ) extends TsecLive[F,
                       SHA256,
                       HMACSHA256,
                       XChaCha20Poly1305,
                       BouncySecretKey] {
//    val x: CryptoHashAPI[SHA256] = SHA256
    override val hasher: CryptoHasher[F, SHA256] =
      implicitly[CryptoHasher[F, SHA256]]
    override val mac: MessageAuth[F, HMACSHA256, MacSigningKey] =
      implicitly[MessageAuth[F, HMACSHA256, MacSigningKey]]
    override val counterStrategy: IvGen[F, XChaCha20Poly1305] =
      XChaCha20Poly1305.defaultIvGen
    override val encryptor
      : AuthEncryptor[F, XChaCha20Poly1305, BouncySecretKey] =
      implicitly[AuthEncryptor[F, XChaCha20Poly1305, BouncySecretKey]]
    override val authCipherAPI
      : AuthCipherAPI[XChaCha20Poly1305, BouncySecretKey] = XChaCha20Poly1305
    override val keyGen
      : SymmetricKeyGen[F, XChaCha20Poly1305, BouncySecretKey] =
      XChaCha20Poly1305.defaultKeyGen
  }

  def apply[F[_]: Sync]: MacaroonService[F] = new Live()
}