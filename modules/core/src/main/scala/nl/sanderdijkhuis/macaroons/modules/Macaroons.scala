package nl.sanderdijkhuis.macaroons.modules

import cats.effect.{IO, Sync}
import cats.{Id, MonadError}
import nl.sanderdijkhuis.macaroons.cryptography.util._
import nl.sanderdijkhuis.macaroons.services.{
  BindingService, CaveatService, MacaroonService
}
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XChaCha20Poly1305}
import tsec.cipher.symmetric.{Encryptor, Iv}
import tsec.hashing.CryptoHasher
import tsec.hashing.jca.SHA256
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.MessageAuth
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

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
