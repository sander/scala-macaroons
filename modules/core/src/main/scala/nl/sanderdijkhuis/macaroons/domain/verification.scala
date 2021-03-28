package nl.sanderdijkhuis.macaroons.domain

import cats.Monoid
import nl.sanderdijkhuis.macaroons.domain.macaroon.Identifier

object verification {

  sealed trait VerificationResult {
    def ||(v: => VerificationResult): VerificationResult
    def isVerified: Boolean
  }
  object VerificationResult {
    def from(b: Boolean): VerificationResult =
      if (b) Verified else VerificationFailed
  }
  case object Verified extends VerificationResult {
    override def ||(v: => VerificationResult): VerificationResult = Verified

    override def isVerified: Boolean = true
  }
  case object VerificationFailed extends VerificationResult {
    override def ||(v: => VerificationResult): VerificationResult = v

    override def isVerified: Boolean = false
  }

  type Verifier = Identifier => VerificationResult

  implicit object VerifierMonoid extends Monoid[Verifier] {
    override def empty: Verifier = _ => VerificationFailed
    override def combine(x: Verifier, y: Verifier): Verifier = c => x(c) || y(c)
  }
}
