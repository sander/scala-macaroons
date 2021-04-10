package nl.sanderdijkhuis.macaroons.codecs

import munit.FunSuite
import nl.sanderdijkhuis.macaroons.codecs.util.seeWhatHappensVector
import scodec.bits._
import scodec.codecs.constant
import scodec.{Attempt, DecodeResult}

class UtilCodecSpec extends FunSuite {

  test("vector of size 0") {
    assert(
      seeWhatHappensVector(constant(hex"01")).decode(hex"0001".bits) ==
        Attempt.Successful(DecodeResult(Vector.empty, hex"0001".bits)))
  }

  test("vector of size 2") {
    assert(
      seeWhatHappensVector(constant(hex"01")).decode(hex"01010001".bits) ==
        Attempt.Successful(DecodeResult(Vector((), ()), hex"0001".bits)))
  }

  test("decoding encoded values") {
    val codec = seeWhatHappensVector(constant(hex"01"))

    def compare(value: Vector[Unit]) =
      codec.decode(codec.encode(value).require).require.value == value

    assert(
      compare(Vector.empty) && compare(Vector(())) && compare(Vector((), ())))
  }
}
