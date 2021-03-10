package nl.sanderdijkhuis.macaroons

import weaver._
import scodec._
import scodec.bits._
import scodec.codecs._
import shapeless._
import io.estatico.newtype.macros.newtype
import scodec.Attempt.Successful

import java.net.URI

object CodecSuite extends SimpleIOSuite {

  @newtype case class Location(value: String)
  @newtype case class Identifier(toByteVector: ByteVector)
  @newtype case class VerificationKeyId(toByteVector: ByteVector)
  @newtype case class AuthenticationTag(toByteVector: ByteVector)

  case class Caveat(maybeLocation: Option[Location],
                    identifier: Identifier,
                    maybeVerificationKeyId: Option[VerificationKeyId])

  case class Macaroon(maybeLocation: Option[Location],
                      identifier: Identifier,
                      caveats: Vector[Caveat],
                      authenticationTag: AuthenticationTag)

  pureTest("foo") {
    def tag(tagInt: Int): Codec[Unit] =
      "tag" | constant(vlong.encode(tagInt).require)
    def lengthValue[A](codec: Codec[A]) =
      "value" | ("length" | vlong).consume(length =>
        limitedSizeBytes(length, codec))(value =>
        codec.encode(value).require.length)
    def requiredField[A](tagInt: Int, codec: Codec[A]): Codec[A] =
      tag(tagInt) ~> lengthValue(codec)
    def optionalField[A](tagInt: Int, codec: Codec[A]): Codec[Option[A]] =
      optional(recover(tag(tagInt)), lengthValue(codec))

    val version = constant(hex"02")
    val endOfSectionBytes = hex"00"
    val endOfSection = constant(endOfSectionBytes)

    val optionalLocation =
      optionalField(1,
                    utf8.exmap[Location](s => Successful(Location(s)),
                                         loc => Successful(loc.toString)))
    val identifier =
      requiredField(2, bytes.xmap[Identifier](Identifier.apply, _.toByteVector))
    val optionalVerificationKeyId = optionalField(
      4,
      bytes.xmap[VerificationKeyId](VerificationKeyId.apply, _.toByteVector))
    val authenticationTag = requiredField(
      6,
      bytes.xmap[AuthenticationTag](AuthenticationTag.apply, _.toByteVector))

    val caveat: Codec[Caveat] =
      (optionalLocation :: identifier :: optionalVerificationKeyId)
        .as[Caveat]

    val macaroon: Codec[Macaroon] =
      (version ~> optionalLocation :: identifier :: vectorDelimited(
        endOfSectionBytes.bits,
        caveat) :: endOfSection :: authenticationTag).as[Macaroon]

    println(
      s"mac: ${macaroon.encode(Macaroon(None, Identifier(hex"aa"), Vector.empty, AuthenticationTag(hex"bb")))}")

    println(
      optional(lookahead(constant(hex"01")), bytes).decode(hex"0111".bits))

    val testje =
      vectorDelimited(hex"20".bits, utf8)
        .decode(ByteVector("hello world".getBytes).bits)
    println(testje)

    expect.all(
      vint.decode(hex"00".bits).require.value == 0,
      vint.decode(hex"01".bits).require.value == 1,
      vint.decode(hex"ac02".bits).require.value == 300,
      vint.encode(0).require == hex"00".bits,
      vint.encode(300).require == hex"ac02".bits
    )
  }
}
