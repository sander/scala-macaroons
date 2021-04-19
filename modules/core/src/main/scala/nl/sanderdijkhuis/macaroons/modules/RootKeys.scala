package nl.sanderdijkhuis.macaroons.modules

import cats.effect._
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.effects._
import nl.sanderdijkhuis.macaroons.repositories._
import tsec.mac.jca
import tsec.mac.jca._

object RootKeys {

  def makeInMemory(): IO[RootKeys[IO]] =
    KeyRepository.inMemoryRef[IO, MacSigningKey[jca.HMACSHA256]]
      .map(repo => RootKeys[IO](repo))
}

case class RootKeys[F[_]](
    repository: KeyRepository[F, Identifier, MacSigningKey[HMACSHA256]])
