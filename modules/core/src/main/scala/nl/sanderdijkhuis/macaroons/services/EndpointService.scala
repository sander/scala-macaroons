package nl.sanderdijkhuis.macaroons.services

import cats.Applicative
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon._

/**
  * Represents a remote principal.
  */
trait EndpointService[F[_]] {

  def prepare(rootKey: RootKey, predicate: Predicate): F[Identifier]

  def maybeLocation: F[Option[Location]]
}

object EndpointService {

  def make[F[_]: Applicative](maybeLoc: Option[Location])(
      f: (RootKey, Predicate) => F[Identifier]): EndpointService[F] =
    new EndpointService[F] {

      override def prepare(rootKey: RootKey,
                           predicate: Predicate): F[Identifier] =
        f(rootKey, predicate)

      override def maybeLocation: F[Option[Location]] = maybeLoc.pure[F]
    }

}
