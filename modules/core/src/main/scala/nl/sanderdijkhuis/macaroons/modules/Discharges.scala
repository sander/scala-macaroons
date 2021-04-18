package nl.sanderdijkhuis.macaroons.modules

import cats.MonadError
import nl.sanderdijkhuis.macaroons.cryptography.util.CryptographyError
import nl.sanderdijkhuis.macaroons.domain.macaroon.{
  Identifier, Location, Predicate
}
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import nl.sanderdijkhuis.macaroons.services.{AssertionService, DischargeService}
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

object Discharges {

  def make[F[_], E >: CryptographyError](maybeLocation: Option[Location])(
      macaroons: Macaroons[F],
      dischargeKeyRepository: KeyRepository[
        F,
        Identifier,
        (MacSigningKey[HMACSHA256], Predicate)])(implicit
      F: MonadError[F, E]): Discharges[F] = {
    val service = DischargeService
      .make[F, E](maybeLocation)(macaroons.service, dischargeKeyRepository)
    Discharges(macaroons, service)
  }
}

final case class Discharges[F[_]] private (
    macaroons: Macaroons[F],
    service: DischargeService[F])
