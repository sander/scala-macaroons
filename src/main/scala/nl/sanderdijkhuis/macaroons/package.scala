package nl.sanderdijkhuis

import cats.effect.Sync
import cats.implicits._
import fs2.Stream
import io.estatico.newtype.macros.newtype
import scodec.bits.ByteVector
import tsec.common.ManagedRandom

import java.util.Base64
import scala.util.chaining._

package object macaroons {

  @newtype case class AuthenticationTag(toByteVector: ByteVector)

  @newtype case class Seal(toByteVector: ByteVector)

  @newtype case class Identifier private (toByteVector: ByteVector)
  object Identifier {

    def from(value: ByteVector): Option[Identifier] = Some(Identifier(value))
  }

  // TODO rename to challenge?
  @newtype case class VerificationKeyId private (toByteVector: ByteVector)
  object VerificationKeyId {

    def from(value: ByteVector): Option[VerificationKeyId] =
      Some(VerificationKeyId(value))
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
  }

  @newtype case class Location private (value: String) {

    override def toString: String = value
  }
  object Location {

    def from(value: String): Option[Location] = Some(Location(value))
  }

  // TODO used?
  @newtype case class Key(toByteVector: ByteVector)

  @newtype case class MacaroonV2(toByteVector: ByteVector) {

    def toBase64url: String =
      Base64.getUrlEncoder.withoutPadding.encodeToString(toByteVector.toArray)
  }
}
