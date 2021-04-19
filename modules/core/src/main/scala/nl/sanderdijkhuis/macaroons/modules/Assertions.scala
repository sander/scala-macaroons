package nl.sanderdijkhuis.macaroons.modules

import nl.sanderdijkhuis.macaroons.cryptography._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.repositories._
import nl.sanderdijkhuis.macaroons.services._

import cats._
import cats.effect._
import tsec.cipher.symmetric.bouncy._
import tsec.mac.jca._

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
