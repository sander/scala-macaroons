package nl.sanderdijkhuis.macaroons

import scodec.Attempt.Successful
import scodec._
import scodec.bits._
import scodec.codecs._
import eu.timepit.refined._
import eu.timepit.refined.api.{RefType, Refined}
import eu.timepit.refined.auto._
import eu.timepit.refined.collection.Size
import eu.timepit.refined.numeric._
import eu.timepit.refined.scodec._
import eu.timepit.refined._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.numeric._
import eu.timepit.refined.api.{RefType, Refined}
import eu.timepit.refined.boolean._
import eu.timepit.refined.char._
import eu.timepit.refined.collection._
import eu.timepit.refined.generic._
import eu.timepit.refined.string._
import eu.timepit.refined.scodec.byteVector._

package object codecs {

  private val version: Codec[Unit] = constant(hex"02")
  private val endOfSectionBytes: ByteVector = hex"00"
  private val endOfSection: Codec[Unit] = constant(endOfSectionBytes)

  private val nonEmptyBytes: Codec[NonEmptyByteVector] =
    bytes.exmap[NonEmptyByteVector](b =>
                                      refineV[NonEmpty](b) match {
                                        case Left(e)  => Attempt.failure(Err(e))
                                        case Right(n) => Attempt.successful(n)
                                    },
                                    n => Attempt.successful(n.value))

  private val optionalLocation: Codec[Option[Location]] =
    optionalField(1,
                  utf8.exmap[Location](s => Successful(Location(s)),
                                       loc => Successful(loc.toString)))
  private val identifier: Codec[Identifier] =
    requiredField(2, nonEmptyBytes.xmap[Identifier](Identifier.apply, _.value))
  private val optionalVerificationKeyId: Codec[Option[Challenge]] =
    optionalField(4, bytes.xmap[Challenge](Challenge.apply, _.toByteVector))
  private val authenticationTag: Codec[AuthenticationTag] =
    requiredField(6,
                  nonEmptyBytes
                    .xmap[AuthenticationTag](AuthenticationTag.apply, _.value))

  private val caveat: Codec[Caveat] =
    (optionalLocation :: identifier :: optionalVerificationKeyId)
      .as[Caveat]
  private val caveats: Codec[Vector[Caveat]] =
    vectorDelimited(endOfSectionBytes.bits, caveat)

  /**
    * @see [[https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt]]
    */
  val macaroonV2: Codec[Macaroon] =
    (version ~> optionalLocation :: identifier :: endOfSection ~> caveats :: endOfSection ~> authenticationTag)
      .as[Macaroon]

  private def tag(tagInt: Int): Codec[Unit] =
    "tag" | constant(vlong.encode(tagInt).require)
  private def lengthValue[A](codec: Codec[A]) =
    "value" | ("length" | vlong).consume(length =>
      limitedSizeBytes(length, codec))(value =>
      codec.encode(value).require.length)
  private def requiredField[A](tagInt: Int, codec: Codec[A]): Codec[A] =
    tag(tagInt) ~> lengthValue(codec)
  private def optionalField[A](tagInt: Int, codec: Codec[A]): Codec[Option[A]] =
    optional(recover(tag(tagInt)), lengthValue(codec))
}
