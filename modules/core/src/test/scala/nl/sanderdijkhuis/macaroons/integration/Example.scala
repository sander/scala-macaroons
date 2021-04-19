package nl.sanderdijkhuis.macaroons.integration

import cats.effect._
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.modules._
import eu.timepit.refined.auto._
import nl.sanderdijkhuis.macaroons.effects.Identifiers
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

object Example {

  val identifiers: Identifiers[IO] = Identifiers.secureRandom
  val rootKeys: RootKeys[IO]       = RootKeys.makeInMemory().unsafeRunSync()
  val assertions: Assertions[IO]   = Assertions.make(rootKeys.repository)

  def main(args: Array[String]): Unit = ()
}
