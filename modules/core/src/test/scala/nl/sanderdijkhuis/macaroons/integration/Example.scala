package nl.sanderdijkhuis.macaroons.integration

import cats.effect._
import nl.sanderdijkhuis.macaroons.effects._
import nl.sanderdijkhuis.macaroons.modules._

object Example {

  val identifiers: Identifiers[IO] = Identifiers.secureRandom
  val rootKeys: RootKeys[IO]       = RootKeys.makeInMemory().unsafeRunSync()
  val assertions: Assertions[IO]   = Assertions.make(rootKeys.repository)

  def main(args: Array[String]): Unit = ()
}
