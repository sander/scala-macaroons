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

  def make[F[_], E >: CryptographyError](
      generateIv: F[InitializationVector])(implicit
      F: MonadError[F, E],
      S: SymmetricKeyGen[F, HMACSHA256, MacSigningKey],
      mac: MessageAuth[F, HMACSHA256, MacSigningKey],
      hasher: CryptoHasher[Id, SHA256],
      encryptor: Encryptor[F, XChaCha20Poly1305, BouncySecretKey])
      : Macaroons[F] = {
    val macaroonService = MacaroonService.make(
      buildMacKey[F, E],
      buildSecretKey[F, E],
      XChaCha20Poly1305.nonceSize)
    Macaroons[F](
      macaroonService,
      CaveatService.make(macaroonService, S.generateKey, generateIv),
      BindingService.make(macaroonService))
  }

  def defaultIvGenerator[F[_]: Sync]: F[Iv[XChaCha20Poly1305]] =
    XChaCha20Poly1305.defaultIvGen[F].genIv

  def make[F[_]: Sync]()(implicit
      S: SymmetricKeyGen[F, HMACSHA256, MacSigningKey],
      mac: MessageAuth[F, HMACSHA256, MacSigningKey],
      hasher: CryptoHasher[Id, SHA256],
      encryptor: Encryptor[F, XChaCha20Poly1305, BouncySecretKey])
      : Macaroons[F] = make[F, Throwable](defaultIvGenerator)

  type RootKey              = MacSigningKey[HMACSHA256]
  type InitializationVector = Iv[XChaCha20Poly1305]
}

final case class Macaroons[F[_]] private (
    private[modules] val service: MacaroonService[
      F,
      Macaroons.RootKey,
      Macaroons.InitializationVector],
    caveats: CaveatService.StatefulCaveatService[F, HMACSHA256],
    binding: BindingService[F])
