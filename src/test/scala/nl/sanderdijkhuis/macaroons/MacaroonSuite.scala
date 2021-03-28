package nl.sanderdijkhuis.macaroons

import cats.effect._
import cats.data._
import cats.implicits._
import eu.timepit.refined.{refineMV, refineV}
import nl.sanderdijkhuis.macaroons.codecs.MacaroonCodec
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

  loggedTest("nicer design") { log =>
    {
      val targetServiceLocation = Location("https://target.example/")
      val forumServiceLocation = Location("https://forum.example/")
      val authenticationServiceLocation =
        Location("https://authentication.example/")

      val chunkInRange = Identifier.from("chunk in {100...500}")
      val opInReadWrite = Identifier.from("op in {read, write}")
      val timeBefore3pm = Identifier.from("time < 5/1/13 3pm")
      val userIsBob = Identifier.from("user = bob")
      val chunkIs235 = Identifier.from("chunk = 235")
      val operationIsRead = Identifier.from("operation = read")
      val timeBefore9am = Identifier.from("time < 5/1/13 9am")
      val ipMatch = Identifier.from("ip = 192.0.32.7")

      for {
        a <- Principal.makeInMemory()
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
        m_ts <- ts.addFirstPartyCaveat(m_ts, timeBefore3pm)
        m_fs <- fs.addThirdPartyCaveat(m_ts, Predicate(userIsBob), asEndpoint)
        m_fs <- fs.addFirstPartyCaveat(m_fs, chunkIs235)
        m_fs <- fs.addFirstPartyCaveat(m_fs, operationIsRead)
        cid <- OptionT
          .fromOption[IO](
            m_fs.caveats.find(_.maybeChallenge.isDefined).map(_.identifier))
          .getOrElseF(IO.raiseError(new Throwable("Could not find 3P caveat")))
        predicate <- as.getPredicate(cid).flatMap {
          case Some(p) => p.pure[IO]
          case None    => IO.raiseError(new Throwable("could not get predicate"))
        }
        _ = println(s"Predicate: $predicate")
        m_as <- as.discharge(cid)
        m_as <- as.addFirstPartyCaveat(m_as, timeBefore9am)
        m_as <- as.addFirstPartyCaveat(m_as, ipMatch)
        m_as_sealed <- MacaroonService[IO].bind(m_fs, m_as)
        result <- ts.verify(
          m_fs,
          p => {
            VerificationResult.from(
              Set(chunkInRange,
                  opInReadWrite,
                  timeBefore3pm,
                  chunkIs235,
                  operationIsRead,
                  timeBefore9am,
                  ipMatch).contains(p))
          },
          Set(m_as_sealed)
        )
      } yield assert(result == Verified)
    }
  }
}
