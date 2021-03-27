package nl.sanderdijkhuis

import cats.Monoid
import cats.effect.Sync
import cats.implicits._
import fs2.Stream
import io.estatico.newtype.macros.newtype
import scodec.bits.ByteVector
import tsec.common.ManagedRandom
import eu.timepit.refined._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.numeric._
import eu.timepit.refined.api.{Failed, Passed, RefType, Refined, Validate}
import eu.timepit.refined.boolean._
import eu.timepit.refined.char._
import eu.timepit.refined.collection._
import eu.timepit.refined.generic._
import eu.timepit.refined.string._
import eu.timepit.refined.scodec.byteVector._
import eu.timepit.refined.types.string.NonEmptyString

import scala.util.chaining._
import scala.language.implicitConversions

package object macaroons {

  trait Authority

  type NonEmptyByteVector = ByteVector Refined NonEmpty

  implicit val validateNonEmptyByteVector: Validate[ByteVector, NonEmpty] =
    Validate.fromPredicate(_.length != 0, b => s"$b is empty", Not(Empty()))

  @newtype case class AuthenticationTag(value: NonEmptyByteVector) {

    def toByteVector: ByteVector = value
  }

  @newtype final case class Identifier(value: NonEmptyByteVector) {

    def toByteVector: ByteVector = value
  }
  object Identifier {

    def from(value: NonEmptyString): Option[Identifier] =
      ByteVector
        .encodeUtf8(value)
        .toOption
        .flatMap(v => refineV[NonEmpty](v).toOption)
        .map(Identifier.apply)
  }

  @newtype case class Predicate(toIdentifier: Identifier)

  @newtype case class Challenge(value: NonEmptyByteVector) {

    def toByteVector: ByteVector = value
  }

  @newtype case class RootKey(value: NonEmptyByteVector) {

    def toByteVector: ByteVector = value
  }

  @newtype case class Location(value: NonEmptyString)

  sealed trait VerificationResult {
    def ||(v: => VerificationResult): VerificationResult
    def isVerified: Boolean
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
