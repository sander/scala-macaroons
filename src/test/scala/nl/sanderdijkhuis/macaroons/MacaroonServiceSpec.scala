package nl.sanderdijkhuis.macaroons

import weaver._
import cats.implicits._
import cats.effect._
import fs2.Stream

object MacaroonServiceSpec extends SimpleIOSuite {

  test("using a stream of caveats multiple times") {
    val caveats = Vector(1, 2, 3)
    val stream = Stream.emits[IO, Int](caveats)
    for {
      a <- stream.map(_ + 1).compile.toList
      b <- stream.map(_ * 2).compile.toList
    } yield assert.all(a == List(2, 3, 4), b == List(2, 4, 6))
  }

  test("x") {
//    MacaroonService.foo(42)
    assert(true).pure[IO]
  }
}
