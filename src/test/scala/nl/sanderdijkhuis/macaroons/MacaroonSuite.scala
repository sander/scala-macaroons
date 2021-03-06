package nl.sanderdijkhuis.macaroons

import cats.effect._
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import weaver._

import java.net.URI

object MacaroonSuite extends SimpleIOSuite {

  implicit def unsafeLogger[F[_]: Sync]: Logger[F] = Slf4jLogger.getLogger[F]

  test("testing") {
    for {
      s <- RootKey.stream.take(3).compile.toList
      x <- IO(
        Capability
          .create(s.head,
                  Identifier("mid".getBytes),
                  Some(Location(new URI("uri"))))
          .attenuate(Identifier("caveat".getBytes))
          .attenuate(RootKey("key".getBytes),
                     Identifier("3p".getBytes),
                     Some(Location(new URI("3ploc")))))
      _ <- Logger[IO].info(s"cap: ${x.marshall().toBase64url}")
    } yield expect(true)
  }
}
