package nl.sanderdijkhuis

import eu.timepit.refined.collection.NonEmpty
import eu.timepit.refined.refineV
import eu.timepit.refined.types.string.NonEmptyString
import nl.sanderdijkhuis.macaroons.{
  NonEmptyByteVector,
  validateNonEmptyByteVector
}
import scodec.Attempt.{Failure, Successful, successful}
import scodec.bits.BitVector
import scodec.codecs.{bytes, utf8}
import scodec.{Attempt, Codec, DecodeResult, Encoder, Err}
import eu.timepit.refined._
import eu.timepit.refined.api.{RefType, Refined}
import eu.timepit.refined.auto._
import eu.timepit.refined.collection.Size
import eu.timepit.refined.numeric._
import eu.timepit.refined.scodec._
import eu.timepit.refined.generic._
import eu.timepit.refined.string._
import eu.timepit.refined.scodec.byteVector._
import eu.timepit.refined.types.string.NonEmptyString

import scala.annotation.tailrec

package object codecs {

  val nonEmptyBytes: Codec[NonEmptyByteVector] =
    bytes.exmap[NonEmptyByteVector](b =>
                                      refineV[NonEmpty](b) match {
                                        case Left(e)  => Attempt.failure(Err(e))
                                        case Right(n) => Attempt.successful(n)
                                    },
                                    n => Attempt.successful(n.value))

  val nonEmptyUtf8: Codec[NonEmptyString] =
    utf8.exmap[NonEmptyString](
      string =>
        refineV[NonEmpty](string) match {
          case Left(e)  => Attempt.failure(Err(e))
          case Right(n) => Attempt.successful(n)
      },
      nonEmptyString => Attempt.successful(nonEmptyString.value)
    )

  def seeWhatHappensVector[A](codec: Codec[A]): Codec[Vector[A]] =
    Codec[Vector[A]](
      Encoder.encodeSeq(codec.asEncoder)(_),
      (bits: BitVector) => {
        @tailrec def helper(rest: BitVector,
                            acc: Vector[A]): Attempt[DecodeResult[Vector[A]]] =
          codec.decode(rest) match {
            case Successful(DecodeResult(v, rem)) => helper(rem, acc :+ v)
            case Failure(_)                       => successful(DecodeResult(acc, rest))
          }
        helper(bits, Vector.empty)
      }
    )
}
