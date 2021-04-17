package nl.sanderdijkhuis.macaroons.integration.example.domain

import io.estatico.newtype.macros.newtype
import nl.sanderdijkhuis.macaroons.domain.macaroon.Macaroon

import java.util.UUID
import scala.language.implicitConversions

object photo {

  @newtype
  case class Photo(value: Array[Byte])

  @newtype
  case class PhotoId(macaroon: Macaroon)
}
