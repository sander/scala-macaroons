package nl.sanderdijkhuis.macaroons

import cats.Monad
import cats.effect.{IO, LiftIO, Sync, SyncIO}
import cats.implicits._
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import scodec.bits.{ByteVector, HexStringSyntax}
import tsec.cipher.symmetric.{
  AuthEncryptor,
  CipherText,
  Iv,
  IvGen,
  PlainText,
  RawCipherText
}
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XSalsa20Poly1305}

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

trait KeyManagement[F[_]] {

  def generateRootKey(): F[RootKey]

  def authenticateAssertion(key: RootKey, identifier: Identifier): F[Tag]

  // make method of macaroon
//  def authenticateCaveat(authentication: Authentication,
//                         maybeChallenge: Option[Challenge],
//                         identifier: Identifier): Authentication

  /**
    * Has effects since encryption is often not deterministic.
    */
  def encryptCaveatRootKey(authentication: Tag, rootKey: RootKey): F[Challenge]

  def decryptCaveatRootKey(authentication: Tag,
                           challenge: Challenge): F[RootKey]

  // make method of macaroon
  //  def bindDischargingToAuthorizing(discharging: Authentication,
//                                   authorizing: Authentication): Authentication
}

object KeyManagement {

  def apply[F[_]](implicit cryptography: KeyManagement[F]): KeyManagement[F] =
    cryptography

  implicit def hmacSHA256AndXChaCha20Poly1305[F[_]: Sync]: KeyManagement[F] =
    new KeyManagement[F] {

      private val algorithm = "HmacSHA256"

      override def authenticateAssertion(key: RootKey,
                                         identifier: Identifier): Tag =
        Tag(hmac(key.toByteVector, identifier.toByteVector))

      override def authenticateCaveat(authentication: Tag,
                                      maybeChallenge: Option[Challenge],
                                      identifier: Identifier): Tag =
        Tag(
          hmac(authentication.toByteVector,
               maybeChallenge
                 .map(_.toByteVector)
                 .getOrElse(ByteVector.empty) ++ identifier.toByteVector))

      // TODO: might make deterministic sometime: [[https://eprint.iacr.org/2020/067]]
      override def encryptCaveatRootKey(authentication: Tag,
                                        key: RootKey): F[Challenge] = {

        implicit val counterStrategy: IvGen[F, XSalsa20Poly1305] =
          XSalsa20Poly1305.defaultIvGen[F] // TODO use ChaCha instead, newer
        implicit val cachedInstance
          : AuthEncryptor[F, XSalsa20Poly1305, BouncySecretKey] =
          XSalsa20Poly1305.authEncryptor

        for {
          k <- XSalsa20Poly1305.defaultKeyGen.build(
            authentication.toByteVector.toArray)
          t = PlainText(key.toByteVector.toArray)
          e <- XSalsa20Poly1305.encrypt[F](t, k)
          c <- Sync[F].delay(Challenge.from(ByteVector(e.toConcatenated)).get)
        } yield c
      }

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

      override def bindDischargingToAuthorizing(discharging: Tag,
                                                authorizing: Tag): Tag =
        Tag(hash(discharging.toByteVector ++ authorizing.toByteVector))

      private def hmac(key: ByteVector, message: ByteVector): ByteVector =
        Mac
          .getInstance(algorithm)
          .tap(_.init(new SecretKeySpec(key.toArray, algorithm)))
          .doFinal(message.toArray)
          .pipe(ByteVector(_))

      private def hash(value: ByteVector): ByteVector =
        MessageDigest
          .getInstance("SHA-256")
          .digest(value.toArray)
          .pipe(ByteVector(_))
    }
}
