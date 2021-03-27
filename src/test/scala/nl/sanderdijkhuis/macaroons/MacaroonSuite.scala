package nl.sanderdijkhuis.macaroons

import cats.effect._
import cats.implicits._
import eu.timepit.refined.{refineMV, refineV}
import scodec.bits.HexStringSyntax
//import cats.implicits._
import nl.sanderdijkhuis.macaroons.codecs.macaroonV2
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import weaver._
import scodec._
import scodec.bits.ByteVector
import scodec.codecs._
import shapeless.{::, HNil}
import eu.timepit.refined._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.numeric._
import eu.timepit.refined.api.{Failed, Passed, RefType, Refined, Validate}
import eu.timepit.refined.boolean._
import eu.timepit.refined.char._
import eu.timepit.refined.collection._
import eu.timepit.refined.generic._
import eu.timepit.refined.string._
import eu.timepit.refined.scodec.byteVector._
import eu.timepit.refined.types.string.NonEmptyString

import java.net.URI

object MacaroonSuite extends SimpleIOSuite {

//  implicit def unsafeLogger[F[_]: Sync]: Logger[F] = Slf4jLogger.getLogger[F]

//  implicit val cryptography: KeyManagement[IO] =
//    KeyManagement.hmacSHA256AndXChaCha20Poly1305[IO]
//
//  implicit val keyService: KeyService[IO] = new KeyService[IO] {
//    override def protectAsFirstParty(key: RootKey): IO[Identifier] =
//      IO.pure(Identifier.from("foo").get)
//
//    override def recoverAsFirstParty(identifier: Identifier): IO[RootKey] = ???
//
//    override def protectAsThirdParty(key: RootKey,
//                                     identifier: Identifier): IO[Identifier] =
//      ???
//
//    /**
//      * 1P will send rootkey + mid to 3P; 3P will return new cid
//      * user will request macaroon for cid; will get one with cid signed with rootkey
//      */
//    override def recoverAsThirdParty(
//        identifier: Identifier): IO[RootKey :: Identifier :: HNil] = ???
//
//    override def generate(): IO[RootKey] = ???
//  }

  private def nonEmptyByteVector(string: NonEmptyString): NonEmptyByteVector =
    ByteVector
      .encodeUtf8(string)
      .toOption
      .flatMap(v => refineV[NonEmpty](v).toOption)
      .get

  loggedTest("nicer design") { log =>
    {
      val keyManagement = KeyManagement[IO]
      val keyRepository = KeyRepository[IO]
      val macaroonService = MacaroonService[IO]
      val location = Location("photo-site")
      val principal =
        Principal.make(Some(location))(keyManagement,
                                       keyRepository,
                                       macaroonService)
      val mid = Identifier(nonEmptyByteVector("mid")) // Identifier.from("mid").get
      val cid = Identifier(nonEmptyByteVector("cid"))
      val vid = Identifier(nonEmptyByteVector("vid"))

      val thirdParty = ThirdParty.make(Some(location)) {
        (rootKey, identifier) =>
          Identifier(nonEmptyByteVector("aa")).pure[IO]
      }

      for {
        macaroon <- principal.assert()
        macaroon <- principal.addFirstPartyCaveat(macaroon, mid)
        macaroon <- principal.addThirdPartyCaveat(macaroon, vid, thirdParty)
        _ = println(s"Macaroon: $macaroon")
        result <- principal.verify(macaroon, _ => VerificationFailed, Set.empty)
        _ = println(s"Result: $result")
      } yield assert(true)
    }
  }

//  import Macaroon.AuthorityOps
//
//  test("serialization") {
//    for {
//      keys <- RootKey.stream.take(2).compile.toList
//      mid <- IO(Identifier.from("mid").get)
//      cid <- IO(Identifier.from("caveat").get)
//      x = Macaroon
//        .create(keys.head, mid, None)
//        .addFirstPartyCaveat(cid)
//      vid <- IO(Identifier.from("3p").get)
//      x2 <- x.addThirdPartyCaveat(keys(1), vid, None)
//      x3 <- x.addThirdPartyCaveat(keys(1), vid, None)
//      y = macaroonV2.encode(x2).require.bytes.toBase64UrlNoPad
////      _ <- Logger[IO].info(s"mac: $y")
//      x <- Principal.Live(None).assert()
////      _ <- Logger[IO].info(s"second: $x")
////      x <- IO.pure(
////        Capability
////          .create(keys.head,
////                  Identifier("mid".getBytes),
////                  Some(Location(new URI("http://example.com/"))))
////          .attenuate(Identifier("caveat".getBytes))
////          .attenuate(RootKey("key".getBytes),
////                     Identifier("3p".getBytes),
////                     Some(Location(new URI("3ploc")))))
////      _ <- Logger[IO].info(s"cap: ${x.marshall().toBase64url}")
////      y <- IO.pure(MacaroonMarshalling.unmarshallMacaroon(x.marshall()))
////      _ <- Logger[IO].info(s"unmarshalled: $y")
//    } yield expect(x2 == x3)
//  }
}
