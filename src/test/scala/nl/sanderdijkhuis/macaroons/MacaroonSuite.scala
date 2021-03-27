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

  private def nonEmptyByteVector(string: NonEmptyString): NonEmptyByteVector =
    ByteVector
      .encodeUtf8(string)
      .toOption
      .flatMap(v => refineV[NonEmpty](v).toOption)
      .get

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
      val mid = Identifier(nonEmptyByteVector("mid")) // Identifier.from("mid").get
      val cid = Identifier(nonEmptyByteVector("cid"))
      val vid = Identifier(nonEmptyByteVector("vid"))

      val thirdParty = ThirdParty.make(Some(location)) {
        (rootKey, identifier) =>
          Identifier(nonEmptyByteVector("aa")).pure[IO]
      }

      val targetService = Location("https://target.example/")
      val forumService = Location("https://forum.example/")
      val authNService = Location("https://authentication.example/")

      for {
        aliceP <- KeyRepository.inMemory.map(Principal.make(None))
        tsP <- KeyRepository.inMemory.map(Principal.make(Some(targetService)))
        fsP <- KeyRepository.inMemory.map(Principal.make(Some(forumService)))
        asP <- KeyRepository.inMemory.map(Principal.make(Some(authNService)))
        bobP <- KeyRepository.inMemory.map(Principal.make(None))
        macaroon <- aliceP.assert()
        macaroon <- aliceP.addFirstPartyCaveat(macaroon, mid)
        macaroon <- aliceP.addThirdPartyCaveat(macaroon, vid, thirdParty)
        _ = println(s"Macaroon: $macaroon")
        _ = println(s"Encoded: ${macaroonV2.encode(macaroon).map(_.bytes)}")
        result <- aliceP.verify(macaroon, _ => VerificationFailed, Set.empty)
        _ = println(s"Result: $result")
      } yield assert(result == VerificationFailed)
    }
  }
}
