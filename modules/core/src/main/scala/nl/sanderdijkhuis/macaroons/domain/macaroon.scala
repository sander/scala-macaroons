package nl.sanderdijkhuis.macaroons.domain

import cats.data.StateT
import eu.timepit.refined.auto._
import eu.timepit.refined.collection.NonEmpty
import eu.timepit.refined.refineV
import eu.timepit.refined.types.string.NonEmptyString
import io.estatico.newtype.macros.newtype
import scodec.bits.ByteVector
import nl.sanderdijkhuis.macaroons.types.bytes._
import scodec.codecs.utf8

import scala.util.chaining._
import scala.language.implicitConversions

object macaroon {

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
      maybeChallenge: Option[Challenge])

  case class Macaroon(
      maybeLocation: Option[Location],
      id: Identifier,
      caveats: Vector[Caveat],
      tag: AuthenticationTag)

  /** Represents a remote principal. */
  case class Context[F[_], RootKey](
      maybeLocation: Option[Location],
      prepare: (RootKey, Predicate) => F[Identifier])

  type Transformation[F[_], A] = StateT[F, Macaroon with Authority, A]
}
