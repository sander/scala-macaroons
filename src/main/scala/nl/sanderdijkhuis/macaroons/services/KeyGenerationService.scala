package nl.sanderdijkhuis.macaroons.services

import cats.effect.Sync
import cats.implicits._
import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.RootKey
import scodec.bits.ByteVector
import tsec.common.SecureRandomId

trait KeyGenerationService[F[_]] {

  def generateRootKey(): F[RootKey]
}

object KeyGenerationService {

  class Live[F[_]: Sync]() extends KeyGenerationService[F] {

    import nl.sanderdijkhuis.macaroons._

    override def generateRootKey(): F[RootKey] =
      for {
        raw <- SecureRandomId.Strong.generateF
        key <- Sync[F].fromEither(
          refineV[NonEmpty](ByteVector(raw.getBytes)).leftMap(new Throwable(_)))
      } yield RootKey(key)
  }

  def apply[F[_]: Sync]: KeyGenerationService[F] = new Live()
}
