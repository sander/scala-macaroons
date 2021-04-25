package nl.sanderdijkhuis.macaroons

import nl.sanderdijkhuis.macaroons.domain._

import eu.timepit.refined.collection._
import eu.timepit.refined.refineV
import eu.timepit.refined.types.string._
import types._
import scodec.Attempt._
import scodec.bits._
import scodec.codecs._
import scodec._

import scala.annotation.tailrec

object codecs {

  import util._

  private val version: Codec[Unit]      = "version" | constant(hex"02")
  private val endOfSection: Codec[Unit] = "eos" | constant(hex"00")

  private val optionalLocation: Codec[Option[Location]] = "opt_location" |
    optionalField(
      1,
      nonEmptyUtf8.exmap[Location](
        s => Successful(Location(s)),
        loc => Successful(loc.value)))

  private val identifier: Codec[Identifier] = "identifier" |
    requiredField(2, nonEmptyBytes.xmap[Identifier](Identifier.apply, _.value))

  private val optionalVerificationKeyId: Codec[Option[Challenge]] = "opt_vid" |
    optionalField(4, nonEmptyBytes.xmap[Challenge](Challenge.apply, _.value))

  private val authenticationTag: Codec[AuthenticationTag] = "signature" |
    requiredField(
      6,
      nonEmptyBytes.xmap[AuthenticationTag](AuthenticationTag.apply, _.value))

  private val caveat: Codec[Caveat] = "caveat" |
    (optionalLocation :: identifier :: optionalVerificationKeyId <~
      endOfSection).as[Caveat]

  private val caveats: Codec[Vector[Caveat]] = "caveats" |
    seeWhatHappensVector(caveat)

  /** @see
    *   [[https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt]]
    */
  val macaroonV2: Codec[Macaroon] =
    (version ~> optionalLocation :: identifier :: endOfSection ~> caveats ::
      endOfSection ~> authenticationTag).as[Macaroon]

  private def tag(tagInt: Int): Codec[Unit] =
    "tag" | constant(vlong.encode(tagInt).require)

  private def requiredField[A](tagInt: Int, codec: Codec[A]): Codec[A] =
    "required" | tag(tagInt) ~> variableSizeBytesLong(vlong, codec)

  private def optionalField[A](tagInt: Int, codec: Codec[A]): Codec[Option[A]] =
    "optional" |
      optional(recover(tag(tagInt)), variableSizeBytesLong(vlong, codec))

  private[macaroons] object util {

    val nonEmptyBytes: Codec[NonEmptyByteVector] = bytes
      .exmap[NonEmptyByteVector](
        b =>
          refineV[NonEmpty](b) match {
            case Left(e)  => Attempt.failure(Err(e))
            case Right(n) => Attempt.successful(n)
          },
        n => Attempt.successful(n.value))

    val nonEmptyUtf8: Codec[NonEmptyString] = utf8.exmap[NonEmptyString](
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
          @tailrec
          def helper(
              rest: BitVector,
              acc: Vector[A]): Attempt[DecodeResult[Vector[A]]] =
            codec.decode(rest) match {
              case Successful(DecodeResult(v, rem)) => helper(rem, acc :+ v)
              case Failure(_)                       => successful(DecodeResult(acc, rest))
            }

          helper(bits, Vector.empty)
        }
      )
  }
}
