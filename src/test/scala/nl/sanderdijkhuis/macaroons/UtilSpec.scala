package nl.sanderdijkhuis.macaroons

import nl.sanderdijkhuis.codecs.seeWhatHappensVector
import scodec._
import scodec.bits._
import scodec.codecs._
import weaver._

object UtilSpec extends SimpleIOSuite {

  pureTest("vector of size 0") {
    assert(
      seeWhatHappensVector(constant(hex"01")).decode(hex"0001".bits) == Attempt
        .Successful(DecodeResult(Vector.empty, hex"0001".bits)))
  }

  pureTest("vector of size 2") {
    assert(
      seeWhatHappensVector(constant(hex"01"))
        .decode(hex"01010001".bits) == Attempt
        .Successful(DecodeResult(Vector((), ()), hex"0001".bits)))
  }

  pureTest("decoding encoded values") {
    val codec = seeWhatHappensVector(constant(hex"01"))
    def compare(value: Vector[Unit]) =
      codec
        .decode(codec.encode(value).require)
        .require
        .value == value
    assert.all(compare(Vector.empty),
               compare(Vector(())),
               compare(Vector((), ())))
  }
}
