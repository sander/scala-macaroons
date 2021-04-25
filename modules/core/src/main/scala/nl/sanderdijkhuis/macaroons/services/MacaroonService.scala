package nl.sanderdijkhuis.macaroons.services

import nl.sanderdijkhuis.design.domain._
import nl.sanderdijkhuis.macaroons.cryptography._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.types._

import cats._
import cats.data._
import cats.implicits._
import cats.tagless._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.collection._
import eu.timepit.refined.refineV
import scodec.bits._
import tsec.cipher.symmetric._
import tsec.hashing._
import tsec.hashing.jca._
import tsec.mac._
import tsec.mac.jca._

import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

/** Operations for generating and manipulating [[Macaroon]]s. */
@finalAlg @autoFunctorK
trait MacaroonService[F[_], RootKey] {

  @Risk("Not enforcing properties of RootKey allows for generating weak keys.")
  private[services] def mint(
      identifier: Identifier,
      maybeLocation: Option[Location] = None)(rootKey: RootKey): F[Macaroon]

  def bind(authorizing: Macaroon, discharging: Macaroon): F[Macaroon]

  private[services] def addFirstPartyCaveat(
      macaroon: Macaroon,
      identifier: Identifier): F[Macaroon]

  private[services] def addThirdPartyCaveat(
      macaroon: Macaroon,
      key: RootKey,
      identifier: Identifier,
      maybeLocation: Option[Location]): F[Macaroon]

  private[services] def verify(
      macaroon: Macaroon,
      verifier: Verifier = Set.empty,
      Ms: Set[Macaroon] = Set.empty)(rootKey: RootKey): F[Boolean]
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
      encryptor: Encryptor[F, AuthCipher, AuthCipherSecretKey],
      initializationVector: F[Iv[AuthCipher]])
      extends MacaroonService[F, MacSigningKey[HmacAlgorithm]] {

    private def unsafeNonEmptyByteVector(
        byteVector: ByteVector): NonEmptyByteVector =
      refineV[NonEmpty].unsafeFrom(byteVector)

    private def bind(
        authorizing: Macaroon,
        dischargingTag: AuthenticationTag): F[AuthenticationTag] =
      (dischargingTag.value ++ authorizing.tag.value).toArray
        .hash[HashAlgorithm]
        .pipe(v => AuthenticationTag(unsafeNonEmptyByteVector(ByteVector(v))))
        .pure[F]

    def bind(authorizing: Macaroon, discharging: Macaroon): F[Macaroon] =
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
        macaroon: Macaroon,
        identifier: Identifier,
        maybeVerificationKeyId: Option[Challenge],
        maybeLocation: Option[Location]): F[Macaroon] = {
      val caveats = macaroon.caveats :+
        Caveat(maybeLocation, identifier, maybeVerificationKeyId)
      authenticateCaveat(macaroon.tag, maybeVerificationKeyId, identifier)
        .map(tag => macaroon.copy(caveats = caveats, tag = tag))
    }

    def mint(identifier: Identifier, maybeLocation: Option[Location])(
        rootKey: MacSigningKey[HmacAlgorithm]): F[Macaroon] =
      authenticate(identifier.value, rootKey)
        .map(Macaroon(maybeLocation, identifier, Vector.empty, _))

    def addFirstPartyCaveat(
        macaroon: Macaroon,
        identifier: Identifier): F[Macaroon] =
      addCaveatHelper(macaroon, identifier, None, None)

    def addThirdPartyCaveat(
        macaroon: Macaroon,
        key: MacSigningKey[HmacAlgorithm],
        identifier: Identifier,
        maybeLocation: Option[Location]): F[Macaroon] =
      for {
        k <- buildEncryptionKey(macaroon.tag.value)
        t = PlainText(key.toJavaKey.getEncoded)
        iv <- initializationVector
        e  <- encryptor.encrypt(t, k, iv)
        c = Challenge(unsafeNonEmptyByteVector(ByteVector(e.toConcatenated)))
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
        macaroon: Macaroon,
        verifier: Verifier,
        macaroons: Set[Macaroon])(
        key: MacSigningKey[HmacAlgorithm]): F[Boolean] = {

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
            case (_, Caveat(_, cId, None)) => verifier(Predicate(cId)).pure[F]
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

      helper(None, key)
    }
  }

  def make[F[
      _]: Monad, E >: CryptographyError, HashAlgorithm, HmacAlgorithm, AuthCipher, AuthCipherSecretKey[
      _]](
      buildMacKey: ByteVector => F[MacSigningKey[HmacAlgorithm]],
      buildSecretKey: ByteVector => F[AuthCipherSecretKey[AuthCipher]],
      nonceSize: Int)(implicit
      mac: MessageAuth[F, HmacAlgorithm, MacSigningKey],
      hasher: CryptoHasher[Id, HashAlgorithm],
      encryptor: Encryptor[F, AuthCipher, AuthCipherSecretKey],
      initializationVector: F[Iv[AuthCipher]])
      : MacaroonService[F, MacSigningKey[HmacAlgorithm]] =
    new TsecLive[
      F,
      HashAlgorithm,
      HmacAlgorithm,
      AuthCipher,
      AuthCipherSecretKey](buildMacKey, buildSecretKey, nonceSize)
}
