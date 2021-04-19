package nl.sanderdijkhuis.macaroons.services

import nl.sanderdijkhuis.macaroons.domain.macaroon.{Authority, Macaroon}

trait BindingService[F[_]] {

  def bind(
      authorizing: Macaroon with Authority,
      discharging: Macaroon): F[Macaroon]
}

object BindingService {

  class BindingServiceLive[F[_], RootKey, InitializationVector](
      macaroonService: MacaroonService[F, RootKey, InitializationVector])
      extends BindingService[F] {

    override def bind(
        authorizing: Macaroon with Authority,
        discharging: Macaroon): F[Macaroon] =
      macaroonService.bind(authorizing, discharging)
  }

  def make[F[_], RootKey, InitializationVector](
      macaroonService: MacaroonService[F, RootKey, InitializationVector])
      : BindingService[F] =
    new BindingServiceLive[F, RootKey, InitializationVector](macaroonService)
}
