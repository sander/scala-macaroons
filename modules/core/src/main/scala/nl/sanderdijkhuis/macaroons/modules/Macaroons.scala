package nl.sanderdijkhuis.macaroons.modules

import cats.MonadError
import nl.sanderdijkhuis.macaroons.cryptography.util.CryptographyError
import nl.sanderdijkhuis.macaroons.services.{CaveatService, MacaroonService}
import tsec.cipher.symmetric.Iv
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

object Macaroons {

  def make[F[_], E >: CryptographyError](
      generateIv: F[InitializationVector])(implicit
      F: MonadError[F, E],
      S: SymmetricKeyGen[F, HMACSHA256, MacSigningKey]): Macaroons[F] = {
    val macaroonService = MacaroonService[F, E]
    Macaroons[F](
      macaroonService,
      CaveatService.make(macaroonService, S.generateKey, generateIv))
  }

  type RootKey              = MacSigningKey[HMACSHA256]
  type InitializationVector = Iv[XChaCha20Poly1305]
}

final case class Macaroons[F[_]] private (
    service: MacaroonService[
      F,
      Macaroons.RootKey,
      Macaroons.InitializationVector],
    caveats: CaveatService.StatefulCaveatService[F, HMACSHA256])
