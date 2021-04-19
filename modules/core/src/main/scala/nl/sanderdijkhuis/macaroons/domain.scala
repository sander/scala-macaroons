package nl.sanderdijkhuis.macaroons

import types._

import cats._
import cats.data._
import eu.timepit.refined.collection._
import eu.timepit.refined.refineV
import eu.timepit.refined.auto._
import eu.timepit.refined.types.string._
import io.estatico.newtype.macros.newtype
import scodec.bits._
import scodec.codecs._

import scala.language.implicitConversions
import scala.util.chaining._

object domain {

  // TODO give better name
  trait Authority

  // TODO could have more precise type
  @newtype
  case class AuthenticationTag(value: NonEmptyByteVector)

  @newtype
  case class Identifier(value: NonEmptyByteVector)

  object Identifier {

    def from(string: NonEmptyString): Identifier =
      ByteVector.encodeUtf8(string).toOption
        .flatMap(v => refineV[NonEmpty](v).toOption).get.pipe(Identifier.apply)

    def from(i: Int): Identifier =
      Identifier(
        refineV[NonEmpty].unsafeFrom(utf8.encode(i.toString).require.bytes))
  }

  @newtype
  case class Predicate(identifier: Identifier)

  object Predicate {

    def from(string: NonEmptyString): Predicate =
      Predicate(Identifier.from(string))
  }

  @newtype
  case class Challenge(value: NonEmptyByteVector)

  @newtype
  case class Location(value: NonEmptyString)

  case class Caveat(
      maybeLocation: Option[Location],
      identifier: Identifier,
      maybeChallenge: Option[Challenge]) {

    override def toString: String =
      s"Caveat{${maybeLocation.map(m => s"$m,").getOrElse("")}${utf8
        .decode(identifier.value.bits).map(_.value).getOrElse(
          identifier.toString)}${maybeChallenge.map(m => s",$m").getOrElse("")}}"
  }

  case class Macaroon(
      maybeLocation: Option[Location],
      id: Identifier,
      caveats: Vector[Caveat],
      tag: AuthenticationTag)

  /** Represents a remote principal. */
  case class Context[F[_], RootKey](
      maybeLocation: Option[Location],
      prepare: (RootKey, Predicate) => F[Identifier])

  type Verifier = Predicate => Boolean

  implicit object VerifierMonoid extends Monoid[Verifier] {
    override def empty: Verifier                             = _ => false
    override def combine(x: Verifier, y: Verifier): Verifier = c => x(c) || y(c)
  }

  type Transformation[F[_], A] = StateT[F, Macaroon with Authority, A]
}
