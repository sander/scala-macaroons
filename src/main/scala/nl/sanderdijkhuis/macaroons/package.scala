package nl.sanderdijkhuis

import cats.Monoid
import io.estatico.newtype.macros.newtype
import scodec.bits.ByteVector
import eu.timepit.refined._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.api._
import eu.timepit.refined.auto._
import eu.timepit.refined.boolean._
import eu.timepit.refined.collection._
import eu.timepit.refined.types.string.NonEmptyString

import scala.language.implicitConversions
import scala.util.chaining._

package object macaroons {

  // TODO give better name
  trait Authority

  type NonEmptyByteVector = ByteVector Refined NonEmpty

  implicit val validateNonEmptyByteVector: Validate[ByteVector, NonEmpty] =
    Validate.fromPredicate(_.length != 0, b => s"$b is empty", Not(Empty()))

  // TODO could have more precise type
  @newtype case class AuthenticationTag(value: NonEmptyByteVector)

  @newtype case class Identifier(value: NonEmptyByteVector)
  object Identifier {

    def from(string: NonEmptyString): Identifier =
      ByteVector
        .encodeUtf8(string)
        .toOption
        .flatMap(v => refineV[NonEmpty](v).toOption)
        .get
        .pipe(Identifier.apply)
  }

  // TODO apply more
  @newtype case class Predicate(identifier: Identifier)

  @newtype case class Challenge(value: NonEmptyByteVector)

  // TODO could have more precise type
  @newtype case class RootKey(value: NonEmptyByteVector)

  @newtype case class Location(value: NonEmptyString)

  case class Caveat(maybeLocation: Option[Location],
                    identifier: Identifier,
                    maybeChallenge: Option[Challenge])

  case class Macaroon(maybeLocation: Option[Location],
                      id: Identifier,
                      caveats: Vector[Caveat],
                      tag: AuthenticationTag)

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
