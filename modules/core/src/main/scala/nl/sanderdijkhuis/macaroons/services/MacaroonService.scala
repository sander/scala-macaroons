package nl.sanderdijkhuis.macaroons.services

import cats._
import cats.data._
import cats.implicits._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.collection._
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.cryptography.util._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.domain.verification._
import nl.sanderdijkhuis.macaroons.types.bytes._
import scodec.bits.ByteVector
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XChaCha20Poly1305}
import tsec.hashing.CryptoHasher
import tsec.hashing.jca.{hashOps, SHA256}
import tsec.mac.MessageAuth
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

/** Operations for generating and manipulating [[Macaroon]]s. */
trait MacaroonService[F[_], RootKey, InitializationVector] {

  def generate(
      identifier: Identifier,
      rootKey: RootKey,
      maybeLocation: Option[Location]): F[Macaroon with Authority]

  def bind(
      authorizing: Macaroon with Authority,
      discharging: Macaroon): F[Macaroon]

  def addFirstPartyCaveat(
      macaroon: Macaroon with Authority,
      identifier: Identifier): F[Macaroon with Authority]

  def addThirdPartyCaveat(
      macaroon: Macaroon with Authority,
      key: RootKey,
      initializationVector: InitializationVector,
      identifier: Identifier,
      maybeLocation: Option[Location]): F[Macaroon with Authority]

  def verify(
      macaroon: Macaroon with Authority,
      key: RootKey,
      verifier: Verifier,
      Ms: Set[Macaroon]): F[VerificationResult]
}

object MacaroonService {

  class TsecLive[F[
      _]: Monad, HashAlgorithm, HmacAlgorithm, AuthCipher, AuthCipherSecretKey[
      _]](
      buildMacKey: ByteVector => F[MacSigningKey[HmacAlgorithm]],
      buildEncryptionKey: ByteVector => F[AuthCipherSecretKey[AuthCipher]],
      nonceSize: Int)(implicit
      mac: MessageAuth[F, HmacAlgorithm, MacSigningKey],
      hasher: CryptoHasher[Id, HashAlgorithm],
      encryptor: Encryptor[F, AuthCipher, AuthCipherSecretKey])
      extends MacaroonService[F, MacSigningKey[HmacAlgorithm], Iv[AuthCipher]] {

    private def unsafeNonEmptyByteVector(
        byteVector: ByteVector): NonEmptyByteVector =
      refineV[NonEmpty].unsafeFrom(byteVector)

    private def bind(
        authorizing: Macaroon with Authority,
        dischargingTag: AuthenticationTag): F[AuthenticationTag] =
      (dischargingTag.value ++ authorizing.tag.value).toArray
        .hash[HashAlgorithm]
        .pipe(v => AuthenticationTag(unsafeNonEmptyByteVector(ByteVector(v))))
        .pure[F]

    def bind(
        authorizing: Macaroon with Authority,
        discharging: Macaroon): F[Macaroon] =
      bind(authorizing, discharging.tag).map(t => discharging.copy(tag = t))

    private def toKey(byteVector: ByteVector): MacSigningKey[HmacAlgorithm] =
      MacSigningKey(new SecretKeySpec(byteVector.toArray, mac.algorithm))

    private def authenticate(
        data: ByteVector,
        key: MacSigningKey[HmacAlgorithm]): F[AuthenticationTag] =
      mac.sign(data.toArray, key).map(ByteVector(_))
        .map(unsafeNonEmptyByteVector).map(AuthenticationTag.apply)

    private def authenticateCaveat(
        tag: AuthenticationTag,
        maybeChallenge: Option[Challenge],
        identifier: Identifier): F[AuthenticationTag] = {
      val data = maybeChallenge.fold(ByteVector.empty)(_.value) ++
        identifier.value
      authenticate(data, toKey(tag.value))
    }

    private def addCaveatHelper(
        macaroon: Macaroon with Authority,
        identifier: Identifier,
        maybeVerificationKeyId: Option[Challenge],
        maybeLocation: Option[Location]): F[Macaroon with Authority] = {
      val caveats = macaroon.caveats :+
        Caveat(maybeLocation, identifier, maybeVerificationKeyId)
      authenticateCaveat(macaroon.tag, maybeVerificationKeyId, identifier)
        .map(tag => macaroon.copy(caveats = caveats, tag = tag))
        .map(_.asInstanceOf[Macaroon with Authority])
    }

    def generate(
        identifier: Identifier,
        rootKey: MacSigningKey[HmacAlgorithm],
        maybeLocation: Option[Location]): F[Macaroon with Authority] =
      authenticate(identifier.value, rootKey).map(tag =>
        Macaroon(maybeLocation, identifier, Vector.empty, tag)
          .asInstanceOf[Macaroon with Authority])

    def addFirstPartyCaveat(
        macaroon: Macaroon with Authority,
        identifier: Identifier): F[Macaroon with Authority] =
      addCaveatHelper(macaroon, identifier, None, None)

    def addThirdPartyCaveat(
        macaroon: Macaroon with Authority,
        key: MacSigningKey[HmacAlgorithm],
        initializationVector: Iv[AuthCipher],
        identifier: Identifier,
        maybeLocation: Option[Location]): F[Macaroon with Authority] =
      for {
        k <- buildEncryptionKey(macaroon.tag.value)
        t = PlainText(key.toJavaKey.getEncoded)
        e <- encryptor.encrypt(t, k, initializationVector)
        c =
          Challenge(refineV[NonEmpty].unsafeFrom(ByteVector(e.toConcatenated)))
        m <- addCaveatHelper(macaroon, identifier, Some(c), maybeLocation)
      } yield m

    def decrypt(
        tag: AuthenticationTag,
        challenge: Challenge): F[MacSigningKey[HmacAlgorithm]] =
      for {
        k <- buildEncryptionKey(tag.value)
        (content, nonce) = challenge.value
          .splitAt(challenge.value.length - nonceSize)
        c = CipherText[AuthCipher](
          RawCipherText(content.toArray),
          Iv(nonce.toArray))
        d   <- encryptor.decrypt(c, k)
        key <- buildMacKey(ByteVector(d))
      } yield key

    def verify(
        macaroon: Macaroon with Authority,
        key: MacSigningKey[HmacAlgorithm],
        verifier: Verifier,
        macaroons: Set[Macaroon]): F[VerificationResult] = {

      def helper(
          discharge: Option[Macaroon],
          k: MacSigningKey[HmacAlgorithm]): F[Boolean] = {
        val M = discharge.getOrElse(macaroon)

        val tags = M.caveats
          .scanLeft(authenticate(M.id.value, k)) { case (cSigF, c) =>
            cSigF.flatMap(authenticateCaveat(_, c.maybeChallenge, c.identifier))
          }
        val verifications = tags.sequence.map(_.zip(M.caveats))
          .flatMap(_.traverse {
            case (_, Caveat(_, cId, None)) => verifier(cId).isVerified.pure[F]
            case (cSig, Caveat(_, id, Some(vId))) => decrypt(cSig, vId)
                .flatMap { key =>
                  macaroons.filter(_.id == id).toList
                    .traverse(m => helper(m.some, key)).map(_.contains(true))
                }
          }).map(!_.contains(false))
        val tag = OptionT(tags.lastOption.sequence).semiflatMap(last =>
          discharge.fold(last.pure[F])(_ => bind(macaroon, last)))
        val tagValidates = tag.map(_ == M.tag).getOrElse(false)
        (verifications, tagValidates).mapN((a, b) => a && b)
      }

      helper(None, key).map(VerificationResult.from)
    }
  }

  type RootKey              = MacSigningKey[HMACSHA256]
  type InitializationVector = Iv[XChaCha20Poly1305]

  def apply[F[_], E >: CryptographyError](implicit F: MonadError[F, E])
      : MacaroonService[F, RootKey, InitializationVector] = {
    implicit val e: Encryptor[F, XChaCha20Poly1305, BouncySecretKey] =
      encryptor[F, E]
    new TsecLive[F, SHA256, HMACSHA256, XChaCha20Poly1305, BouncySecretKey](
      buildMacKey[F, E],
      buildEncryptionKey[F, E],
      XChaCha20Poly1305.nonceSize)
  }
}
