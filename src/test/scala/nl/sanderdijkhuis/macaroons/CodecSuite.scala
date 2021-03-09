package nl.sanderdijkhuis.macaroons

import weaver._
import scodec._
import scodec.bits._
import scodec.codecs._

import java.net.URI

object CodecSuite extends SimpleIOSuite {
  val firstCodec = uint8 :: uint8 :: uint16

  case class Caveat(location: Option[String],
                    identifier: ByteVector,
                    optionalVerificationKey: Option[ByteVector])

//  val caveatCodec: Codec[Caveat] = (int8 :: int8 :: int8).as[Caveat]

  case class Macaroon(location: Option[String],
                      identifier: ByteVector,
                      caveats: List[Caveat])

  //MacaroonV2(
  //        version ++ optionalLocation(macaroon) ++ identifier(macaroon) ++ endOfSection ++ caveats(
  //          macaroon) ++ endOfSection ++ signature(macaroon))

//  val locationCodec: Codec[String] = {
//    (constant(hex"0x01")) :: (scodec.codecs.ignore(3))
//  }.as[String]
//  val stringCodec: Codec[String] = ???
//  val locationCodec = constant(hex"0x01") :~>: (uint16 >>:~ (length =>
//    limitedSizeBytes(
//      length,
//      stringCodec /*.xmap[URI](s => new URI(s), loc => loc.toString))
//      .xmap[Location](Location.apply, _.toURI)*/ )))

  pureTest("foo") {
    def field[A](tag: Int, codec: Codec[A]) =
      ("tag" | constant(vlong.encode(tag).require)) :~>: ("value" | (("length" | vlong) >>:~ (
          length => limitedSizeBytes(length, codec.hlist))))
    val locationTag = 1
    val identifierTag = 2
    val verificationIdTag = 4
    val signatureTag = 6
//    val x = field.exmap[Field](a => a.head match {
//      case x if x == locationTag => Attempt.successful(Location(new URI(a.tail.head.decodeUtf8)))
//    }
    val endOfSection = constant(hex"00")
    val version = constant(hex"02")
    val result = field(locationTag, utf8).decode(hex"0102414243".bits)
    println(result)

    expect.all(
      vint.decode(hex"00".bits).require.value == 0,
      vint.decode(hex"01".bits).require.value == 1,
      vint.decode(hex"ac02".bits).require.value == 300,
      vint.encode(0).require == hex"00".bits,
      vint.encode(300).require == hex"ac02".bits
    )
  }

}
