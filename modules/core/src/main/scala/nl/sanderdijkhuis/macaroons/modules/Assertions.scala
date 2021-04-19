package nl.sanderdijkhuis.macaroons.modules

import cats.MonadError
import cats.effect.Sync
import cats.implicits._
import nl.sanderdijkhuis.macaroons.cryptography.util.CryptographyError
import nl.sanderdijkhuis.macaroons.domain.macaroon.{Identifier, Location}
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import nl.sanderdijkhuis.macaroons.services.AssertionService
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

object Assertions {

  def make[F[_], E >: CryptographyError](
      macaroons: Macaroons[F],
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HMACSHA256]],
      generateKey: F[MacSigningKey[HMACSHA256]],
      maybeLocation: Option[Location])(implicit
      F: MonadError[F, E]): Assertions[F] = {
    val service = AssertionService.make[F, E, HMACSHA256, XChaCha20Poly1305](
      maybeLocation)(macaroons.service, rootKeyRepository, generateKey)
    Assertions(macaroons, service)
  }

  private def make[F[_]: Sync](
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HMACSHA256]],
      maybeLocation: Option[Location]): Assertions[F] =
    make[F, Throwable](
      Macaroons.make(),
      rootKeyRepository,
      HMACSHA256.generateKey[F],
      maybeLocation)

  def make[F[_]: Sync](
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HMACSHA256]],
      location: Location): Assertions[F] =
    make[F](rootKeyRepository, Some(location))

  def make[F[_]: Sync](
      rootKeyRepository: KeyRepository[
        F,
        Identifier,
        MacSigningKey[HMACSHA256]]): Assertions[F] =
    make[F](rootKeyRepository, None)
}

final case class Assertions[F[_]] private (
    macaroons: Macaroons[F],
    service: AssertionService[F])
