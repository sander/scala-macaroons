package nl.sanderdijkhuis.macaroons.modules

import cats.MonadError
import cats.effect.Sync
import nl.sanderdijkhuis.macaroons.cryptography.util.CryptographyError
import nl.sanderdijkhuis.macaroons.domain.macaroon.{Identifier, Location}
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import nl.sanderdijkhuis.macaroons.services.AssertionService
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

object Assertions {

  def make[F[_], E >: CryptographyError](
      maybeLocation: Option[Location],
      macaroons: Macaroons[F],
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HMACSHA256]],
      generateKey: F[MacSigningKey[HMACSHA256]])(implicit
      F: MonadError[F, E]): Assertions[F] = {
    val service = AssertionService.make[F, E, HMACSHA256, XChaCha20Poly1305](
      maybeLocation)(macaroons.service, rootKeyRepository, generateKey)
    Assertions(macaroons, service)
  }

  def make[F[_]: Sync](
      maybeLocation: Option[Location],
      macaroons: Macaroons[F],
      rootKeyRepository: KeyRepository[
        F,
        Identifier,
        MacSigningKey[HMACSHA256]]): Assertions[F] =
    make[F, Throwable](
      maybeLocation,
      macaroons,
      rootKeyRepository,
      HMACSHA256.generateKey[F])
}

final case class Assertions[F[_]] private (
    macaroons: Macaroons[F],
    service: AssertionService[F])
