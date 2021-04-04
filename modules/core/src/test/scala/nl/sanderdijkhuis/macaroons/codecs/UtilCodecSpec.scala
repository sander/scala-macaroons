package nl.sanderdijkhuis.macaroons.codecs

import nl.sanderdijkhuis.macaroons.codecs.util.seeWhatHappensVector
import scodec.codecs.constant
import scodec.{Attempt, DecodeResult}
import weaver.SimpleIOSuite
import scodec.codecs._
import scodec.bits._

object UtilCodecSpec extends SimpleIOSuite {

  pureTest("vector of size 0") {
    assert(
      seeWhatHappensVector(constant(hex"01")).decode(hex"0001".bits) ==
        Attempt.Successful(DecodeResult(Vector.empty, hex"0001".bits)))
  }

  pureTest("vector of size 2") {
    assert(
      seeWhatHappensVector(constant(hex"01")).decode(hex"01010001".bits) ==
        Attempt.Successful(DecodeResult(Vector((), ()), hex"0001".bits)))
  }

  pureTest("decoding encoded values") {
    val codec = seeWhatHappensVector(constant(hex"01"))

    def compare(value: Vector[Unit]) =
      codec.decode(codec.encode(value).require).require.value == value

    assert
      .all(compare(Vector.empty), compare(Vector(())), compare(Vector((), ())))
  }
}
