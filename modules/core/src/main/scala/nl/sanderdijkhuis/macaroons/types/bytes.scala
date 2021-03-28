package nl.sanderdijkhuis.macaroons.types

import eu.timepit.refined.api.{Refined, Validate}
import eu.timepit.refined.boolean.Not
import eu.timepit.refined.collection.{Empty, NonEmpty}
import scodec.bits.ByteVector

object bytes {

  type NonEmptyByteVector = ByteVector Refined NonEmpty

  implicit val validateNonEmptyByteVector: Validate[ByteVector, NonEmpty] =
    Validate.fromPredicate(_.length != 0, b => s"$b is empty", Not(Empty()))
}
