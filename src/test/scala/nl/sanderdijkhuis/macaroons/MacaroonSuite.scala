package nl.sanderdijkhuis.macaroons

import cats.effect._
//import cats.implicits._
import nl.sanderdijkhuis.macaroons.codecs.macaroonV2
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import weaver._
import scodec._
import scodec.bits.ByteVector
import scodec.codecs._
import shapeless.{::, HNil}

import java.net.URI

object MacaroonSuite extends SimpleIOSuite {

//  implicit def unsafeLogger[F[_]: Sync]: Logger[F] = Slf4jLogger.getLogger[F]

  implicit val cryptography: Cryptography[IO] =
    Cryptography.hmacSHA256AndXChaCha20Poly1305[IO]

  implicit val keyService: KeyService[IO] = new KeyService[IO] {
    override def protectAsFirstParty(key: RootKey): IO[Identifier] =
      IO.pure(Identifier.from("foo").get)

    override def recoverAsFirstParty(identifier: Identifier): IO[RootKey] = ???

    override def protectAsThirdParty(key: RootKey,
                                     identifier: Identifier): IO[Identifier] =
      ???

    /**
      * 1P will send rootkey + mid to 3P; 3P will return new cid
      * user will request macaroon for cid; will get one with cid signed with rootkey
      */
    override def recoverAsThirdParty(
        identifier: Identifier): IO[RootKey :: Identifier :: HNil] = ???

    override def generate(): IO[RootKey] = ???
  }

  loggedTest("nicer design") { log =>
    for {
      p <- Principal(Some("photo-site"))
      m <- p.assert()
    } yield assert(true)
  }

  import Macaroon.AuthorityOps

  test("serialization") {
    for {
      keys <- RootKey.stream.take(2).compile.toList
      mid <- IO(Identifier.from("mid").get)
      cid <- IO(Identifier.from("caveat").get)
      x = Macaroon
        .create(keys.head, mid, None)
        .addFirstPartyCaveat(cid)
      vid <- IO(Identifier.from("3p").get)
      x2 <- x.addThirdPartyCaveat(keys(1), vid, None)
      x3 <- x.addThirdPartyCaveat(keys(1), vid, None)
      y = macaroonV2.encode(x2).require.bytes.toBase64UrlNoPad
//      _ <- Logger[IO].info(s"mac: $y")
      x <- Principal.Live(None).assert()
//      _ <- Logger[IO].info(s"second: $x")
//      x <- IO.pure(
//        Capability
//          .create(keys.head,
//                  Identifier("mid".getBytes),
//                  Some(Location(new URI("http://example.com/"))))
//          .attenuate(Identifier("caveat".getBytes))
//          .attenuate(RootKey("key".getBytes),
//                     Identifier("3p".getBytes),
//                     Some(Location(new URI("3ploc")))))
//      _ <- Logger[IO].info(s"cap: ${x.marshall().toBase64url}")
//      y <- IO.pure(MacaroonMarshalling.unmarshallMacaroon(x.marshall()))
//      _ <- Logger[IO].info(s"unmarshalled: $y")
    } yield expect(x2 == x3)
  }
}
