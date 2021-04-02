package nl.sanderdijkhuis.macaroons.repositories

import cats.Applicative
import cats.data.StateT
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon.Identifier

trait KeyRepository[F[_], Key] {

  def protect(key: Key): F[Identifier]

  def recover(identifier: Identifier): F[Option[Key]]
}

object KeyRepository {

  private class InMemory[F[_]: Applicative, Key](
      generateIdentifier: F[Identifier])
      extends KeyRepository[StateT[F, Map[Identifier, Key], *], Key] {

    type Effect[A] = StateT[F, Map[Identifier, Key], A]

    override def protect(key: Key): Effect[Identifier] =
      StateT(s => generateIdentifier.map(id => (s + (id -> key), id)))

    override def recover(identifier: Identifier): Effect[Option[Key]] =
      StateT(s => (s, s.get(identifier)).pure[F])
  }

  def inMemory[F[_]: Applicative, Key](generateIdentifier: F[Identifier])
    : KeyRepository[StateT[F, Map[Identifier, Key], *], Key] =
    new InMemory[F, Key](generateIdentifier)
}
