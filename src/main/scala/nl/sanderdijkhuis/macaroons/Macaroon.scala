package nl.sanderdijkhuis.macaroons

import fs2.Stream
import cats.{Applicative, Monad}
import cats.effect.Sync
import cats.implicits._
import org.bouncycastle.jcajce.provider.symmetric.XSalsa20
import scodec.bits.ByteVector
import tsec.cipher.symmetric.{
  AuthCipherAPI,
  AuthEncryptor,
  CipherText,
  Iv,
  IvGen,
  PlainText,
  RawCipherText
}
import tsec.cipher.symmetric.bouncy.{
  BouncySecretKey,
  XChaCha20Poly1305,
  XSalsa20Poly1305
}
import tsec.mac.jca.HMACSHA256
import tsec.common._
import tsec.hashing.{CryptoHashAPI, CryptoHasher}
import tsec.hashing.jca.SHA256
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.{MAC, MessageAuth}
import tsec.mac.jca._

import java.security.MessageDigest
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

case class Macaroon(maybeLocation: Option[Location],
                    identifier: Identifier,
                    caveats: Vector[Caveat],
                    tag: Tag)

object Macaroon {

//  def create[F[_]](key: RootKey,
//                   identifier: Identifier,
//                   maybeLocation: Option[Location])(
//      implicit cryptography: KeyManagement[F]): Macaroon with Authority =
//    Macaroon(maybeLocation,
//             identifier,
//             Vector.empty,
//             cryptography.authenticateAssertion(key, identifier))
//      .asInstanceOf[Macaroon with Authority]

  trait MacaroonService[F[_]] {

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

  class AuthorityOps2impl[F[_]: Sync,
                          HashAlgorithm,
                          HmacAlgorithm,
                          AuthCipher,
                          AuthCipherSecretKey[_]]()(
      implicit val hasher: CryptoHasher[F, HashAlgorithm],
      mac: MessageAuth[F, HmacAlgorithm, MacSigningKey],
      counterStrategy: IvGen[F, AuthCipher],
      encryptor: AuthEncryptor[F, AuthCipher, AuthCipherSecretKey],
      authCipherAPI: AuthCipherAPI[AuthCipher, AuthCipherSecretKey],
      keyGen: SymmetricKeyGen[F, AuthCipher, AuthCipherSecretKey])
      extends MacaroonService[F] {

    private def bind(authorizing: Macaroon with Authority,
                     dischargingTag: Tag): F[Tag] =
      hasher
        .hash((dischargingTag ++ authorizing.tag).toArray)
        .map(Tag(_))

    def bind(authorizing: Macaroon with Authority,
             discharging: Macaroon): F[Macaroon] =
      bind(authorizing, discharging.tag).map(t => discharging.copy(tag = t))

    private def toKey(byteVector: ByteVector): MacSigningKey[HmacAlgorithm] =
      MacSigningKey(new SecretKeySpec(byteVector.toArray, mac.algorithm))

    private def authenticate(data: ByteVector,
                             key: MacSigningKey[HmacAlgorithm]): F[Tag] =
      mac.sign(data.toArray, key).map(Tag(_))

    private def authenticateCaveat(tag: Tag,
                                   maybeChallenge: Option[Challenge],
                                   identifier: Identifier): F[Tag] = {
      val data = maybeChallenge.fold(ByteVector.empty)(_.toByteVector) ++ identifier.toByteVector
      authenticate(data, toKey(tag.toByteVector))
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
        k <- keyGen.build(macaroon.tag.toByteVector.toArray)
        t = PlainText(key.toByteVector.toArray)
        e <- authCipherAPI.encrypt[F](t, k)
        c <- Sync[F].delay(Challenge.from(ByteVector(e.toConcatenated)).get)
        m <- addCaveatHelper(macaroon, identifier, Some(c), maybeLocation)
      } yield m

    /*
         override def decryptCaveatRootKey(
          authentication: Tag,
          challenge: Challenge): Option[RootKey] = {

        implicit val counterStrategy: IvGen[SyncIO, XSalsa20Poly1305] =
          XSalsa20Poly1305.defaultIvGen
        implicit val cachedInstance
          : AuthEncryptor[SyncIO, XSalsa20Poly1305, BouncySecretKey] =
          XSalsa20Poly1305.authEncryptor

        val program = for {
          k <- XSalsa20Poly1305
            .defaultKeyGen[SyncIO]
            .build(authentication.toByteVector.toArray)
          (content, nonce) = challenge.toByteVector.splitAt(
            challenge.toByteVector.length - 24) // TODO
          c = CipherText[XSalsa20Poly1305](RawCipherText(content.toArray),
                                           Iv(nonce.toArray))
          d <- XSalsa20Poly1305.decrypt(c, k)
          key <- SyncIO(RootKey.from(ByteVector(d)).get)
        } yield key

        program
          .map(Some(_))
          .handleErrorWith(_ => SyncIO.pure(None))
          .unsafeRunSync()
      }
     */

    def decrypt(tag: Tag, challenge: Challenge): F[RootKey] =
      for {
        k <- keyGen.build(tag.toByteVector.toArray)
        (content, nonce) = challenge.toByteVector.splitAt(
          challenge.toByteVector.length - 24) // TODO
        c = CipherText[AuthCipher](RawCipherText(content.toArray),
                                   Iv(nonce.toArray))
        d <- authCipherAPI.decrypt(c, k)
        key <- Sync[F].delay(RootKey.from(ByteVector(d)).get)
      } yield key

    def verify(macaroon: Macaroon with Authority,
               key: RootKey,
               verifier: Verifier,
               Ms: Set[Macaroon]): F[VerificationResult] = {
      def helper(discharge: Option[Macaroon], k: RootKey): F[Boolean] = {
        val M = discharge.getOrElse(macaroon)
        val caveats = Stream.emits[F, Caveat](M.caveats)
        val signatures = for {
          cSig <- Stream.eval(
            authenticate(M.identifier.toByteVector, toKey(k.toByteVector)))
          tag <- caveats.evalScan(cSig) {
            case (cSig, Caveat(_, cId, vId)) =>
              authenticateCaveat(cSig, vId, cId)
          }
        } yield tag
        val verifications = caveats.zip(signatures).flatMap {
          case (Caveat(_, cId, None), _) => Stream.emit(verifier(cId))
          case (Caveat(_, cId, Some(vId)), cSig) =>
            for {
              key <- Stream.eval(decrypt(cSig, vId))
              result <- Stream
                .emits[F, Macaroon](Ms.toSeq)
                .filter(_.identifier == cId)
                .evalMap(m => helper(Some(m), key))
                .find(_ == true)
                .lastOr(false)
            } yield result
        }
        val allVerifications =
          verifications.forall(_ == true).compile.last.map(_.isDefined)
        val tagCheck = for {
          maybeLast <- signatures.compile.last
          last <- Sync[F].fromOption(maybeLast, new Throwable("No signatures"))
          sig <- discharge match {
            case Some(_) => bind(macaroon, last)
            case None    => Sync[F].pure(last)
          }
        } yield sig == M.tag
        for {
          a <- allVerifications
          b <- tagCheck
        } yield a && b
      }
      helper(None, key).map(b => if (b) Verified else VerificationFailed)
    }
  }

  implicit class AuthorityOps[F[_]: Applicative, A](
      macaroon: Macaroon with Authority)(
      implicit keyManagement: KeyManagement[F],
      hasher: CryptoHasher[F, A]) {

    // TODO too specific
    private def hash(value: ByteVector): ByteVector =
      MessageDigest
        .getInstance("SHA-256")
        .digest(value.toArray)
        .pipe(ByteVector(_))

    val toMac: Array[Byte] = "hi!".utf8Bytes

    def `mac'd-pure`[F[_]: Sync]: F[Boolean] =
      for {
        key <- HMACSHA256.generateKey[F] //Generate our key.
        macValue <- HMACSHA256.sign[F](toMac, key) //Generate our MAC bytes
        verified <- HMACSHA256
          .verifyBool[F](toMac, macValue, key) //Verify a byte array with a signed, typed instance
      } yield verified

    private def bindForRequest2[A](authentication: Tag)(
        implicit hasher: CryptoHasher[F, A]): F[Tag] =
      hasher
        .hash(
          (authentication.toByteVector ++ macaroon.tag.toByteVector).toArray)
        .map(Tag.apply)

//    private def bindForRequest(authentication: Authentication)(
//        implicit cryptography: KeyManagement[F]): Authentication =
//      SHA256
//      cryptography.bindDischargingToAuthorizing(authentication,
//                                                macaroon.authentication)

    private def addCaveatHelper(identifier: Identifier,
                                maybeVerificationKeyId: Option[Challenge],
                                maybeLocation: Option[Location])(
        implicit cryptography: KeyManagement[F]): Macaroon with Authority =
      macaroon
        .copy(
          caveats = macaroon.caveats :+ Caveat(maybeLocation,
                                               identifier,
                                               maybeVerificationKeyId),
          tag = cryptography.authenticateCaveat(macaroon.tag,
                                                maybeVerificationKeyId,
                                                identifier)
        )
        .asInstanceOf[Macaroon with Authority]

//    def bind2(macaroons:Set[Macaroon]):F[Set[Macaroon]] =
    def bind2[A](discharging: Macaroon)(
        hasher: CryptoHasher[F, A]): F[Macaroon] =
      bindForRequest2(discharging.tag)(hasher)
        .map(a => discharging.copy(tag = a))

    def bind(capabilities: Set[Macaroon])(
        implicit cryptography: KeyManagement[F]): Set[Macaroon] =
      capabilities.map(
        d =>
          Macaroon(d.maybeLocation,
                   d.identifier,
                   d.caveats,
                   bindForRequest(d.tag)))

    def addFirstPartyCaveat(identifier: Identifier)(
        implicit cryptography: KeyManagement[F]): Macaroon with Authority =
      addCaveatHelper(identifier, None, None)

    def addThirdPartyCaveat(key: RootKey,
                            identifier: Identifier,
                            maybeLocation: Option[Location])(
        implicit cryptography: KeyManagement[F]): F[Macaroon with Authority] =
      cryptography
        .encryptCaveatRootKey(macaroon.tag, key)
        .map(c => addCaveatHelper(identifier, Some(c), maybeLocation))

    def verify(key: RootKey, verifier: Verifier, Ms: Set[Macaroon])(
        implicit cryptography: KeyManagement[F]): VerificationResult = {
      def helper(discharge: Option[Macaroon],
                 k: RootKey): VerificationResult = {
        val M = discharge.getOrElse(macaroon)
        val cSig = cryptography.authenticateAssertion(k, M.identifier)
        val maybeAuthentication =
          M.caveats
            .foldLeft[Option[Tag]](Some(cSig)) {
              case (Some(cSig), Caveat(_, cId, vId)) => {
                val caveatsVerified = vId match {
                  case None => verifier(cId)
                  case Some(vId)
                      if Ms.exists(
                        m =>
                          (m.identifier == cId) && cryptography
                            .decryptCaveatRootKey(cSig, vId)
                            .map(helper(Some(m), _).isVerified)
                            .isDefined) =>
                    Verified
                  case _ => VerificationFailed
                }
                Option.when(caveatsVerified.isVerified)(
                  cryptography.authenticateCaveat(cSig, vId, cId))
              }
              case (None, _) => None
            }
        (maybeAuthentication, discharge) match {
          case (Some(cSig), Some(M)) if M.tag == bindForRequest(cSig) =>
            Verified
          case (Some(cSig), None) if macaroon.tag == cSig => Verified
          case _                                          => VerificationFailed
        }
      }
      helper(None, key)
    }
  }
}
