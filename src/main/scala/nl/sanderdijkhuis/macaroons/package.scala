package nl.sanderdijkhuis

import cats.Monoid
import cats.effect.Sync
import cats.implicits._
import fs2.Stream
import io.estatico.newtype.macros.newtype
import scodec.bits.ByteVector
import tsec.common.ManagedRandom

import scala.util.chaining._
import scala.language.implicitConversions

package object macaroons {

  trait Authority

  @newtype case class AuthenticationTag private (toByteVector: ByteVector) {

    def ++(other: AuthenticationTag): ByteVector =
      toByteVector ++ other.toByteVector
  }
  object AuthenticationTag {

    def apply(byteArray: Array[Byte]): AuthenticationTag =
      AuthenticationTag(ByteVector(byteArray))
  }

  @newtype final case class Identifier private (toByteVector: ByteVector)
  object Identifier {

    def from(value: ByteVector): Option[Identifier] = Some(Identifier(value))

    def from(value: String): Option[Identifier] =
      ByteVector.encodeUtf8(value).toOption.flatMap(from)
  }

  @newtype case class Predicate(toIdentifier: Identifier)

  @newtype case class Challenge private (toByteVector: ByteVector)
  object Challenge {

    def from(value: ByteVector): Option[Challenge] =
      Some(Challenge(value))
  }

  @newtype case class RootKey private (toByteVector: ByteVector)
  object RootKey {

    def stream[F[_]: Sync]: Stream[F, RootKey] =
      for {
        m <- Stream.eval[F, ManagedRandom](Sync[F].delay(new ManagedRandom {}))
        k <- Stream
          .eval(
            Sync[F]
              .delay(new Array[Byte](32).tap(m.nextBytes))
              .map(ByteVector(_)))
          .repeat
      } yield RootKey(k)

    def from(value: ByteVector): Option[RootKey] = Some(RootKey(value))

    def from(value: Array[Byte]): Option[RootKey] = from(ByteVector(value))
  }

  @newtype case class Location private (value: String)
  object Location {

    def from(value: String): Option[Location] = Some(Location(value))
  }

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
