package nl.sanderdijkhuis.macaroons.integration.example.effects

import java.time.Instant

trait Time[F[_]] {

  def get(): F[Instant]
}

object Time {

  def apply[F[_]: Time]: Time[F] = implicitly
}
