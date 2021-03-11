package nl.sanderdijkhuis.macaroons

import nl.sanderdijkhuis.macaroons
import scodec.bits._
import scodec.codecs._
import weaver._

object CodecSuite extends SimpleIOSuite {

  pureTest("foo") {
    println(s"mac: ${macaroons.Codec.macaroon.encode(macaroons.Codec
      .Macaroon(None, Identifier(hex"aa"), Vector.empty, AuthenticationTag(hex"bb")))}")

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
