package nl.sanderdijkhuis.macaroons

import weaver._
import scodec._
import scodec.bits._
import scodec.codecs._
import shapeless._
import io.estatico.newtype.macros.newtype
import nl.sanderdijkhuis.macaroons
import scodec.Attempt.Successful

import java.net.URI

object CodecSuite extends SimpleIOSuite {

  pureTest("foo") {
    println(s"mac: ${macaroons.Codec.macaroon.encode(macaroons.Codec
      .Macaroon(None, macaroons.Codec.Identifier(hex"aa"), Vector.empty, macaroons.Codec.AuthenticationTag(hex"bb")))}")

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
