package nl.sanderdijkhuis.macaroons

import weaver._

object VarintSuite extends SimpleIOSuite {
  pureTest("encode") {
    expect.all(
      Varint.encode(0) sameElements Array[Byte](0x0),
      Varint.encode(1) sameElements Array[Byte](0x1),
      Varint.encode(300) sameElements Array[Byte](0xac.toByte, 0x2.toByte)
    )
  }

  pureTest("decode 0") {
    val result = Varint
      .decodeToInt(Array[Byte](0x0), Varint.Offset(0))
    expect.all(result.get._1 == 0, result.get._2 == Varint.Offset(1))
  }

  pureTest("decode 300") {
    val result = Varint
      .decodeToInt(Array[Byte](0xac.toByte, 0x2.toByte), Varint.Offset(0))
    expect.all(result.get._1 == 300, result.get._2 == Varint.Offset(2))
  }
}
