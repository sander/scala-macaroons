package nl.sanderdijkhuis.macaroons.cryptography

import cats._
import cats.effect._
import cats.implicits._
import scodec.bits.ByteVector
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XChaCha20Poly1305}
import tsec.cipher.symmetric.{CipherText, Encryptor, Iv, PlainText}
import tsec.mac.jca.{HMACSHA256, MacErrorM, MacSigningKey}
import tsec.mac.{MAC, MessageAuth}

object util {

  sealed trait CryptographyError            extends Throwable
  case class EncryptionError(value: String) extends CryptographyError
  case class KeyGenError(value: String)     extends CryptographyError

  implicit def messageAuth[F[_]: Monad](implicit
      original: MessageAuth[MacErrorM, HMACSHA256, MacSigningKey])
      : MessageAuth[F, HMACSHA256, MacSigningKey] = {
    val fk: MacErrorM ~> F = λ[MacErrorM ~> F](s => s.toOption.get.pure[F])
    new MessageAuth[F, HMACSHA256, MacSigningKey] {
      def algorithm: String = original.algorithm

      def sign(
          in: Array[Byte],
          key: MacSigningKey[HMACSHA256]): F[MAC[HMACSHA256]] =
        fk(original.sign(in, key))

      def verifyBool(
          in: Array[Byte],
          hashed: MAC[HMACSHA256],
          key: MacSigningKey[HMACSHA256]): F[Boolean] =
        fk(original.verifyBool(in, hashed, key))
    }
  }

  implicit def encryptor[F[_]](implicit
      F: MonadError[F, CryptographyError],
      e: Encryptor[IO, XChaCha20Poly1305, BouncySecretKey])
      : Encryptor[F, XChaCha20Poly1305, BouncySecretKey] = {
    val fk: IO ~> F = λ[IO ~> F](s =>
      MonadError[F, CryptographyError].fromEither(
        s.attempt.unsafeRunSync().leftMap(t => EncryptionError(t.getMessage))))
    new Encryptor[F, XChaCha20Poly1305, BouncySecretKey] {
      def encrypt(
          plainText: PlainText,
          key: BouncySecretKey[XChaCha20Poly1305],
          iv: Iv[XChaCha20Poly1305]): F[CipherText[XChaCha20Poly1305]] =
        fk(e.encrypt(plainText, key, iv))

      def decrypt(
          cipherText: CipherText[XChaCha20Poly1305],
          key: BouncySecretKey[XChaCha20Poly1305]): F[PlainText] =
        fk(e.decrypt(cipherText, key))
    }
  }

  def buildMacKey[F[_]](in: ByteVector)(implicit
      F: MonadError[F, CryptographyError]): F[MacSigningKey[HMACSHA256]] =
    MonadError[F, CryptographyError]
      .fromEither(HMACSHA256.buildKey[MacErrorM](in.toArray).leftMap(t =>
        KeyGenError(t.getMessage)))

  def buildEncryptionKey[F[_]](in: ByteVector)(implicit
      F: MonadError[F, CryptographyError])
      : F[BouncySecretKey[XChaCha20Poly1305]] = {
    val key = XChaCha20Poly1305.defaultKeyGen[IO].build(in.toArray).attempt
      .unsafeRunSync()
    MonadError[F, CryptographyError]
      .fromEither(key.leftMap(t => KeyGenError(t.getMessage)))
  }
}
