package nl.sanderdijkhuis.macaroons

import cats.{Applicative, Monad}
import cats.effect.Sync
import cats.implicits._
import scodec.bits.ByteVector
import tsec.mac.jca.HMACSHA256
import tsec.common._
import tsec.hashing.{CryptoHashAPI, CryptoHasher}
import tsec.hashing.jca.SHA256
import tsec.mac.MessageAuth
import tsec.mac.jca._

import java.security.MessageDigest
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

  trait MacaroonService[F[_], Hash] {

    def bind(authorizing: Macaroon with Authority,
             discharging: Macaroon): F[Macaroon]
  }

  class AuthorityOps2impl[F[_]: Monad,
                          HashAlgorithm,
                          HmacAlgorithm,
                          MacSigningKey]()(
      implicit val hasher: CryptoHasher[F, HashAlgorithm],
      mac: MessageAuth[F, HmacAlgorithm, MacSigningKey])
      extends MacaroonService[F, HashAlgorithm] {

    def bind(authorizing: Macaroon with Authority,
             discharging: Macaroon): F[Macaroon] =
      hasher
        .hash((discharging.tag ++ authorizing.tag).toArray)
        .map(a => discharging.copy(tag = Tag(a)))

    /*

      override def authenticateCaveat(authentication: Tag,
                                      maybeChallenge: Option[Challenge],
                                      identifier: Identifier): Tag =
        Tag(
          hmac(authentication.toByteVector,
               maybeChallenge
                 .map(_.toByteVector)
                 .getOrElse(ByteVector.empty) ++ identifier.toByteVector))

     */

    private def addCaveatHelper(
        macaroon: Macaroon with Authority,
        identifier: Identifier,
        maybeVerificationKeyId: Option[Challenge],
        maybeLocation: Option[Location]): F[Macaroon with Authority] =
      macaroon
        .copy(
          caveats = macaroon.caveats :+ Caveat(maybeLocation,
                                               identifier,
                                               maybeVerificationKeyId),
          tag = cryptography.authenticateCaveat(macaroon.tag,
                                                maybeVerificationKeyId,
                                                identifier) // mac.sign
        )
        .asInstanceOf[Macaroon with Authority]
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
