package nl.sanderdijkhuis.macaroons.modules

import nl.sanderdijkhuis.macaroons.cryptography._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.repositories._
import nl.sanderdijkhuis.macaroons.services._

import cats._
import tsec.mac.jca._

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
