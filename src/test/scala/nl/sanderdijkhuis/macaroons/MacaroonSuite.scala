package nl.sanderdijkhuis.macaroons

import cats.effect._
import cats.implicits._
import eu.timepit.refined.{refineMV, refineV}
import nl.sanderdijkhuis.macaroons.codecs.{
  MacaroonCodec,
//  lengthValue,
//  lengthValue2
}
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

  private def bytes(string: NonEmptyString): NonEmptyByteVector =
    ByteVector
      .encodeUtf8(string)
      .toOption
      .flatMap(v => refineV[NonEmpty](v).toOption)
      .get

  pureTest("y") {
    expect(utf8.encode("https://target.example/").require.bytes.length == 23L)
  }

  pureTest("z") {
    expect(vlong.encode(23L).require.toHex == "17")
  }

  pureTest("wrong") {
    expect(vlong.decodeValue(hex"b801".bits).require == 23L)
  }

  pureTest("good") {
    expect(vlong.decodeValue(hex"17".bits).require == 23L)
  }

//  pureTest("refactor") {
//    val s = "https://target.example/"
//    println(
//      lengthValue2(utf8)
//        .encode(s)
//        .require)
//    expect(
//      lengthValue(utf8).encode(s).require == lengthValue2(utf8)
//        .encode(s)
//        .require)
//  }

  loggedTest("nicer design") { log =>
    {
      val keyManagement = KeyManagement[IO]
//      val keyRepository = KeyRepository.inMemory[IO].unsafeRunSync()
      val macaroonService = MacaroonService[IO]
      val location = Location("photo-site")
//      val principal =
//        Principal.make(Some(location))(keyManagement,
//                                       keyRepository,
//                                       macaroonService)
      val mid = Identifier(bytes("mid")) // Identifier.from("mid").get
      val cid = Identifier(bytes("cid"))
      val vid = Identifier(bytes("vid"))

      val targetServiceLocation = Location("https://target.example/")
      val forumServiceLocation = Location("https://forum.example/")
      val authenticationServiceLocation =
        Location("https://authentication.example/")

      val remoteAuthenticationService =
        ThirdParty.make(Some(authenticationServiceLocation)) {
          (rootKey, identifier) =>
            Identifier(bytes("aa")).pure[IO]
        }

      val chunkInRange = Identifier.from("chunk in {100...500}")
      val opInReadWrite = Identifier.from("op in {read, write}")
      val timeBefore = Identifier.from("time < 5/1/13 3pm")
      val userIsBob = Identifier.from("user = bob")

      for {
        a <- Principal.makeInMemory() // return Principal and Endpoint?
        ts <- Principal.makeInMemory(targetServiceLocation)
        fs <- Principal.makeInMemory(forumServiceLocation)
        asRepository <- KeyRepository.inMemory
        as = Principal.make(Some(authenticationServiceLocation))(asRepository)
        asEndpoint = ThirdParty.make(Some(authenticationServiceLocation))(
          asRepository.protectRootKeyAndPredicate)
        bob <- Principal.makeInMemory()
        m_ts <- ts.assert()
        m_ts <- ts.addFirstPartyCaveat(m_ts, chunkInRange)
        m_ts <- ts.addFirstPartyCaveat(m_ts, opInReadWrite)
        m_ts <- ts.addFirstPartyCaveat(m_ts, timeBefore)
        _ = println(s"Macaroon: $m_ts")
        x <- MacaroonCodec.encode[IO](m_ts)
        _ = println(s"Encoded: $x")
        y <- MacaroonCodec.decodeAuthorizing[IO](x)
        _ = println(s"Decoded: $y")
//        m_fs <- MacaroonCodec
//          .encode[IO](m_ts)
//          .flatMap(MacaroonCodec.decodeAuthorizing[IO])
//        m_fs <- fs.addThirdPartyCaveat(m_fs, userIsBob, asEndpoint)
//         TODO encode and decode, will lose Authority then
//        _ = println(s"Encoded: ${macaroonV2.encode(m_fs).map(_.bytes)}")
//        result <- ts.verify(m_ts, _ => VerificationFailed, Set.empty)
//        _ = println(s"Result: $result")
      } yield assert(m_ts == y)
      //assert(result == VerificationFailed)
    }
  }
}
