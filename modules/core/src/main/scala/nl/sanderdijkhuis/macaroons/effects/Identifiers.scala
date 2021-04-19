package nl.sanderdijkhuis.macaroons.effects

import cats.effect._
import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.domain.macaroon.Identifier
import nl.sanderdijkhuis.macaroons.types.bytes._
import scodec.bits.ByteVector
import tsec.common.ManagedRandom

trait Identifiers[F[_]] {

  def make(): F[Identifier]
}

object Identifiers {

  def apply[F[_]: Identifiers]: Identifiers[F] = implicitly

  private val sizeInBytes: Int = 16

  private object Generator extends ManagedRandom {

    def generate[F[_]: Sync]: F[Identifier] =
      Sync[F].delay {
        val byteArray = new Array[Byte](sizeInBytes)
        nextBytes(byteArray)
        Identifier(refineV[NonEmpty].unsafeFrom(ByteVector(byteArray)))
      }
  }

  implicit def secureRandom[F[_]: Sync]: Identifiers[F] =
    () => Generator.generate[F]
}
