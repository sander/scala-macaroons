package nl.sanderdijkhuis.macaroons.integration.example.effects

import cats.effect.Sync

import java.util.UUID

trait UUIDs[F[_]] {

  def make(): F[UUID]
}

object UUIDs {

  def apply[F[_]: UUIDs]: UUIDs[F] = implicitly

  implicit def syncUUIDs[F[_]: Sync]: UUIDs[F] =
    () => Sync[F].delay(UUID.randomUUID())
}
