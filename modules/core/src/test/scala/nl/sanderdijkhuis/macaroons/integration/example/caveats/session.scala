package nl.sanderdijkhuis.macaroons.integration.example.caveats

import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.domain.macaroon.Identifier
import nl.sanderdijkhuis.macaroons.integration.example.domain.authentication.Challenge

import java.time.Instant

object session {

  def timeBefore(instant: Instant): Identifier =
    Identifier
      .from(refineV[NonEmpty].unsafeFrom(s"time < ${instant.toEpochMilli}"))

  def challengeEquals(challenge: Challenge): Identifier =
    Identifier
      .from(refineV[NonEmpty].unsafeFrom(s"challenge = ${challenge.value}"))
}
