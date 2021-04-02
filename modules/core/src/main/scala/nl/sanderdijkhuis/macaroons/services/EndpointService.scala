package nl.sanderdijkhuis.macaroons.services

import nl.sanderdijkhuis.macaroons.domain.macaroon._

/**
  * Represents a remote principal.
  */
trait EndpointService[F[_], RootKey] {

  def prepare(rootKey: RootKey, predicate: Predicate): F[Identifier]

  def maybeLocation: Option[Location]
}

object EndpointService {

  def make[F[_], RootKey](maybeLoc: Option[Location])(
      f: (RootKey, Predicate) => F[Identifier]): EndpointService[F, RootKey] =
    new EndpointService[F, RootKey] {
      override def prepare(rootKey: RootKey,
                           predicate: Predicate): F[Identifier] =
        f(rootKey, predicate)

      override def maybeLocation: Option[Location] = maybeLoc
    }
}
