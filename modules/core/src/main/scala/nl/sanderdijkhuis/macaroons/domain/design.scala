package nl.sanderdijkhuis.macaroons.domain

import scala.annotation.Annotation

object design {

  case class Risk(description: String) extends Annotation
}
