package nl.sanderdijkhuis.macaroons.domain

import cats.Monoid
import nl.sanderdijkhuis.macaroons.domain.macaroon.{Identifier, Predicate}

object verification {

  type Verifier = Predicate => Boolean

  implicit object VerifierMonoid extends Monoid[Verifier] {
    override def empty: Verifier                             = _ => false
    override def combine(x: Verifier, y: Verifier): Verifier = c => x(c) || y(c)
  }
}
