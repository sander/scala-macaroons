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

  @newtype case class Authentication(toByteVector: ByteVector)

  @newtype final case class Identifier private (toByteVector: ByteVector)
  object Identifier {

    def from(value: ByteVector): Option[Identifier] = Some(Identifier(value))

    def from(value: String): Option[Identifier] =
      ByteVector.encodeUtf8(value).toOption.flatMap(from)
  }

  @newtype case class Challenge private (toByteVector: ByteVector)
  object Challenge {

    def from(value: ByteVector): Option[Challenge] =
      Some(Challenge(value))
  }

  @newtype case class Key private (toByteVector: ByteVector)
  object Key {

    def stream[F[_]: Sync]: Stream[F, Key] =
      for {
        m <- Stream.eval[F, ManagedRandom](Sync[F].delay(new ManagedRandom {}))
        k <- Stream
          .eval(
            Sync[F]
              .delay(new Array[Byte](32).tap(m.nextBytes))
              .map(ByteVector(_)))
          .repeat
      } yield Key(k)

    def from(value: ByteVector): Option[Key] = Some(Key(value))
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
