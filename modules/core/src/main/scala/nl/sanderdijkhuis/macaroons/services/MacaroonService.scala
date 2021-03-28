package nl.sanderdijkhuis.macaroons.services

import cats._
import cats.data._
import cats.effect._
import cats.implicits._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.collection._
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.types.bytes._
import fs2.Stream
import nl.sanderdijkhuis.macaroons.domain.verification._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import scodec.bits.ByteVector
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XChaCha20Poly1305}
import tsec.hashing.CryptoHasher
import tsec.hashing.jca.SHA256
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.MessageAuth
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

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
    }

    private def bind(authorizing: Macaroon with Authority,
                     dischargingTag: AuthenticationTag): F[AuthenticationTag] =
      hash(dischargingTag.value ++ authorizing.tag.value)
        .map(AuthenticationTag.apply)

    def bind(authorizing: Macaroon with Authority,
             discharging: Macaroon): F[Macaroon] =
      bind(authorizing, discharging.tag).map(t => discharging.copy(tag = t))

    private def toKey(byteVector: ByteVector): MacSigningKey[HmacAlgorithm] =
      MacSigningKey(new SecretKeySpec(byteVector.toArray, mac.algorithm))

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
        val tags = for {
          cSig <- Stream.eval(authenticate(M.id.value, toKey(k.value)))
          tag <- caveats.evalScan(cSig)((cSig, c) =>
            authenticateCaveat(cSig, c.maybeChallenge, c.identifier))
        } yield tag
        val verifications = caveats.zip(tags).evalMap {
          case (Caveat(_, cId, None), _) => verifier(cId).isVerified.pure[F]
          case (Caveat(_, id, Some(vId)), cSig) =>
            decrypt(cSig, vId).flatMap(key =>
              Ms.filter(_.id == id).evalMap(m => helper(m.some, key)).some)
        }
        val tag = OptionT(tags.compile.last).semiflatMap(last =>
          discharge.fold(last.pure[F])(_ => bind(macaroon, last)))
        val tagValidates = tag.map(_ == M.tag).getOrElse(false)
        verifications.all && tagValidates
      }

      helper(None, key).map(VerificationResult.from)
    }
  }

  implicit class EffectOps[F[_]: Monad](aF: F[Boolean]) {
    def &&(bF: F[Boolean]): F[Boolean] = aF.flatMap(a => bF.map(b => a && b))
  }
  implicit class StreamOps[F[_]: Sync](s: Stream[F, Boolean]) {
    def all: F[Boolean] =
      s.forall(v => v).compile.toList.map(_ == List(true))
    def some: F[Boolean] =
      s.filter(v => v).head.compile.last.map(_.isDefined)
  }

  class Live[F[_]]()(
      implicit override val sync: Sync[F],
  ) extends TsecLive[F,
                       SHA256,
                       HMACSHA256,
                       XChaCha20Poly1305,
                       BouncySecretKey] {
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
