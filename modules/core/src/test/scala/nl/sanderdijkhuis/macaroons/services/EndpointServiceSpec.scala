package nl.sanderdijkhuis.macaroons.services

import cats.effect.IO
import cats.implicits._
import eu.timepit.refined.auto._
import nl.sanderdijkhuis.macaroons.domain.macaroon.{
  Identifier,
  Location,
  Predicate
}
import tsec.mac.jca.{HMACSHA256, MacSigningKey}
import weaver._

object EndpointServiceSpec extends SimpleIOSuite {

  pureTest("keeps the location") {
    val location = Location("https://example.com/")
    def protect(rootKey: MacSigningKey[HMACSHA256], predicate: Predicate) =
      Identifier.from("id").pure[IO]
    val loc1 = EndpointService.make(None)(protect).maybeLocation
    val loc2 = EndpointService.make(Some(location))(protect).maybeLocation
    assert.all(loc1.isEmpty, loc2.contains(location))
  }
}
