package nl.sanderdijkhuis.macaroons.codecs

import cats.effect._
import cats.implicits._
import nl.sanderdijkhuis.macaroons.codecs.util._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import scodec.Attempt.Successful
import scodec._
import scodec.bits._
import scodec.codecs._

object macaroon {

  private val version: Codec[Unit] = "version" | constant(hex"02")
  private val endOfSection: Codec[Unit] = "eos" | constant(hex"00")

  private val optionalLocation: Codec[Option[Location]] =
    "opt_location" | optionalField(
      1,
      nonEmptyUtf8.exmap[Location](s => Successful(Location(s)),
                                   loc => Successful(loc.value)))

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
    "caveat" | (optionalLocation :: identifier :: optionalVerificationKeyId <~ endOfSection)
      .as[Caveat]

  private val caveats: Codec[Vector[Caveat]] =
    "caveats" | seeWhatHappensVector(caveat)

  /**
    * @see [[https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt]]
    */
  val macaroonV2: Codec[Macaroon] =
    (version ~> optionalLocation :: identifier :: endOfSection ~> caveats :: endOfSection ~> authenticationTag)
      .as[Macaroon]

  private def tag(tagInt: Int): Codec[Unit] =
    "tag" | constant(vlong.encode(tagInt).require)
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
