package nl.sanderdijkhuis.macaroons

import eu.timepit.refined.api._
import eu.timepit.refined.boolean._
import eu.timepit.refined.collection._
import scodec.bits._

object types {

  type NonEmptyByteVector = ByteVector Refined NonEmpty

  implicit val validateNonEmptyByteVector: Validate[ByteVector, NonEmpty] =
    Validate.fromPredicate(_.length != 0, b => s"$b is empty", Not(Empty()))
}
