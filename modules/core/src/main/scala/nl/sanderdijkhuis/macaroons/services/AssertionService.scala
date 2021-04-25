package nl.sanderdijkhuis.macaroons.services

import cats.data.Kleisli
import nl.sanderdijkhuis.macaroons.domain.{
  Identifier, Location, Macaroon, Verifier
}

trait AssertionService[F[_]] {

  def mint(
      identifier: Identifier,
      maybeLocation: Option[Location] = None): F[Macaroon]

  def verify(
      macaroon: Macaroon,
      verifier: Verifier = Set.empty,
      Ms: Set[Macaroon] = Set.empty): F[Boolean]
}

object AssertionService {

  class Live[F[_], RootKey](macaroonService: MacaroonService[F, RootKey])
      extends AssertionService[Kleisli[F, RootKey, *]] {

    override def mint(
        identifier: Identifier,
        maybeLocation: Option[Location]): Kleisli[F, RootKey, Macaroon] =
      Kleisli(macaroonService.mint(identifier, maybeLocation))

    override def verify(
        macaroon: Macaroon,
        verifier: Verifier,
        Ms: Set[Macaroon]): Kleisli[F, RootKey, Boolean] =
      Kleisli(macaroonService.verify(macaroon, verifier, Ms))
  }

  def make[F[_], RootKey](macaroonService: MacaroonService[F, RootKey])
      : AssertionService[Kleisli[F, RootKey, *]] =
    new Live[F, RootKey](macaroonService)
}
