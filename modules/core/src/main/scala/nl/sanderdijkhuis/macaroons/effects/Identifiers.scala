package nl.sanderdijkhuis.macaroons.effects

import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.types._

import cats.effect._
import eu.timepit.refined.predicates.all._
import eu.timepit.refined.refineV
import scodec.bits._
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
