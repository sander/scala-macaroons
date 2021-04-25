package nl.sanderdijkhuis.macaroons.modules

import nl.sanderdijkhuis.macaroons.cryptography._
import nl.sanderdijkhuis.macaroons.services._

import cats._
import cats.effect._
import tsec.cipher.symmetric.bouncy._
import tsec.cipher.symmetric._
import tsec.hashing._
import tsec.hashing.jca._
import tsec.keygen.symmetric._
import tsec.mac._
import tsec.mac.jca._

object Macaroons {

  def make[F[_], E >: CryptographyError](implicit
      F: MonadError[F, E],
      S: SymmetricKeyGen[F, HMACSHA256, MacSigningKey],
      mac: MessageAuth[F, HMACSHA256, MacSigningKey],
      hasher: CryptoHasher[Id, SHA256],
      encryptor: Encryptor[F, XChaCha20Poly1305, BouncySecretKey],
      generateIv: F[InitializationVector]): Macaroons[F] = {
    val macaroonService = MacaroonService.make(
      buildMacKey[F, E],
      buildSecretKey[F, E],
      XChaCha20Poly1305.nonceSize)
    Macaroons[F](
      macaroonService,
      CaveatService.make(macaroonService, S.generateKey))
  }

  def make[F[_]: Sync]()(implicit
      S: SymmetricKeyGen[F, HMACSHA256, MacSigningKey],
      mac: MessageAuth[F, HMACSHA256, MacSigningKey],
      hasher: CryptoHasher[Id, SHA256],
      encryptor: Encryptor[F, XChaCha20Poly1305, BouncySecretKey])
      : Macaroons[F] = {
    implicit val iv: F[Iv[XChaCha20Poly1305]] = XChaCha20Poly1305
      .defaultIvGen[F].genIv
    make[F, Throwable]
  }

  type RootKey              = MacSigningKey[HMACSHA256]
  type InitializationVector = Iv[XChaCha20Poly1305]
}

final case class Macaroons[F[_]] private (
    service: MacaroonService[F, Macaroons.RootKey],
    caveats: CaveatService.StatefulCaveatService[F, HMACSHA256])
