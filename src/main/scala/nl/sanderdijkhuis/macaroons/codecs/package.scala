package nl.sanderdijkhuis.macaroons

import cats._
import cats.effect._
import cats.implicits._
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
import eu.timepit.refined.types.string.NonEmptyString

package object codecs {

  private val version: Codec[Unit] = "version" | constant(hex"02")
  private val endOfSection: Codec[Unit] = "eos" | constant(hex"00")

  private val nonEmptyBytes: Codec[NonEmptyByteVector] =
    bytes.exmap[NonEmptyByteVector](b =>
                                      refineV[NonEmpty](b) match {
                                        case Left(e)  => Attempt.failure(Err(e))
                                        case Right(n) => Attempt.successful(n)
                                    },
                                    n => Attempt.successful(n.value))
  private val nonEmptyUtf8: Codec[NonEmptyString] =
    utf8.exmap[NonEmptyString](
      string =>
        refineV[NonEmpty](string) match {
          case Left(e)  => Attempt.failure(Err(e))
          case Right(n) => Attempt.successful(n)
      },
      nonEmptyString => Attempt.successful(nonEmptyString.value)
    )

  private val optionalLocation: Codec[Option[Location]] =
    "opt_location" | optionalField(
      1,
      nonEmptyUtf8.exmap[Location](s => Successful(Location(s)),
                                   loc => Successful(loc.value)))

//  private val optionalLocation: Codec[Option[Location]] =
//    optionalField(
//      1,
//      utf8.exmap[Location](s =>
//                             refineV[NonEmpty](s) match {
//                               case Left(e)  => Attempt.failure(Err(e))
//                               case Right(n) => Successful(Location(n))
//                           },
//                           loc => Successful(loc.value))
//    )
  private val identifier: Codec[Identifier] =
    "identifier" | requiredField(
      2,
      nonEmptyBytes.xmap[Identifier](Identifier.apply, _.value))
  private val optionalVerificationKeyId: Codec[Option[Challenge]] =
    "opt_vid" | optionalField(
      4,
      nonEmptyBytes.xmap[Challenge](Challenge.apply, _.value))
  private val authenticationTag: Codec[AuthenticationTag] =
    "signature" | requiredField(
      6,
      nonEmptyBytes
        .xmap[AuthenticationTag](AuthenticationTag.apply, _.value))

  private val caveat: Codec[Caveat] =
    "caveat" | (optionalLocation :: identifier :: optionalVerificationKeyId)
      .as[Caveat]
  private val caveats: Codec[Vector[Caveat]] =
    "caveats" | vectorDelimited(endOfSection.encode(()).require, caveat)

  /**
    * @see [[https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt]]
    */
  val macaroonV2: Codec[Macaroon] =
    (version ~> optionalLocation :: identifier :: endOfSection ~> caveats :: endOfSection ~> authenticationTag)
      .as[Macaroon]

//  val macaroonV2WithAuthority: Codec[Macaroon with Authority] =
//    macaroonV2.xmap(_.asInstanceOf[Macaroon with Authority], v => v)

  private def tag(tagInt: Int): Codec[Unit] =
    "tag" | constant(vlong.encode(tagInt).require)
//  def lengthValue[A](codec: Codec[A]) =
//    "value" | ("length" | vlong).consume(length => {
//      println(s"limited size $length $codec")
//      limitedSizeBytes(length, codec)
//    })(value => {
//      codec.encode(value).require.length
//    })
//  def lengthValue2[A](codec: Codec[A]): Codec[A] =
//    variableSizeBytesLong(vlong, codec)
//    vlong.consume(length => limitedSizeBytes(length, codec))(value =>
//      codec.encode(value).require.length)
  private def requiredField[A](tagInt: Int, codec: Codec[A]): Codec[A] =
    "required" | tag(tagInt) ~> variableSizeBytesLong(vlong, codec)
  private def optionalField[A](tagInt: Int, codec: Codec[A]): Codec[Option[A]] =
    "optional" | optional(recover(tag(tagInt)),
                          variableSizeBytesLong(vlong, codec))

  object MacaroonCodec {
    def encode[F[_]: Sync](macaroon: Macaroon): F[ByteVector] =
      Sync[F].fromTry(macaroonV2.encode(macaroon).toTry).map(_.bytes)
    def decode[F[_]: Sync](byteVector: ByteVector): F[Macaroon] =
      Sync[F]
        .delay(macaroonV2.decodeValue(byteVector.bits).require)
    def decodeAuthorizing[F[_]: Sync](
        byteVector: ByteVector): F[Macaroon with Authority] =
      decode(byteVector)
        .map(_.asInstanceOf[Macaroon with Authority])
  }
}
