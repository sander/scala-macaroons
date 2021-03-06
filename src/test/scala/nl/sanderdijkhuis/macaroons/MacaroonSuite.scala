package nl.sanderdijkhuis.macaroons

import cats.{MonadError, Monoid}
import cats.data._
import weaver._
import cats.effect._
import com.github.nitram509.jmacaroons.util.BinHex
import com.github.nitram509.jmacaroons.{
  CaveatPacket,
  GeneralCaveatVerifier,
  GeneralSecurityRuntimeException,
  Macaroon,
  MacaroonValidationException,
  MacaroonsBuilder,
  MacaroonsVerifier
}
import org.typelevel.log4cats.Logger
import org.typelevel.log4cats.slf4j.Slf4jLogger
import tsec.common.{ManagedRandom, SecureRandomId, SecureRandomIdGenerator}
import fs2.Stream

import java.net.URI
import scala.language.implicitConversions
import scala.util.{Failure, Success, Try}
import scala.util.chaining._

object MacaroonSuite extends SimpleIOSuite {
  val randomUUID = IO(java.util.UUID.randomUUID())

  implicit def unsafeLogger[F[_]: Sync] = Slf4jLogger.getLogger[F]

  // A test for side-effecting functions
  test("hello side-effects") {
    for {
      x <- randomUUID
      y <- randomUUID
    } yield expect(x != y)
  }

  // TODO find nicer ubiquitous language with "authority" etc

  test("create a simple macaroon") {
    for {
      s <- RootKey.stream.take(3).compile.toList
      _ <- Logger[IO].info(s"Keys: $s")
      mac <- IO(
        new MacaroonsBuilder("https://example.com/", s.head.value, "my-id")
          .add_first_party_caveat("account = 123")
          .add_first_party_caveat("foo = bar")
          .getMacaroon)
//      x = mac.caveatPackets.head.getType
      _ <- Logger[IO].info(s"Mac: ${mac.serialize()}")
      _ <- Logger[IO].info(s"Sig: ${mac.signature}")
      verifier <- IO(new MacaroonsVerifier(mac))
      _ <- Logger[IO].info(s"Verifying: ${verifier.isValid(s.head.value)}")
      _ <- Logger[IO].info(s"Verifying2: ${Verifier(mac, s.head)}")
      res <- Verifier.x[IO, Throwable](new MacaroonsVerifier(mac), s.head)
      _ <- Logger[IO].info(s"Verifying3: $res")
      res2 <- Verifier.x[IO, Throwable](new MacaroonsVerifier(mac)
                                          .satisfyExact("account = 123")
                                          .satisfyExact("foo = bar"),
                                        s.head)
      _ <- Logger[IO].info(s"Verifying4: $res2")
      res3 <- Verifier.x[IO, Throwable](new MacaroonsVerifier(mac)
                                          .satisfyExact("foo = bar")
                                          .satisfyExact("account = 123")
                                          .satisfyExact("asdf"),
                                        s.head)
      _ <- Logger[IO].info(s"Verifying5: $res3")
      //      _ <- IO(verifier.assertIsValid(s.head.value))
    } yield expect(mac != null)
  }

//  test("new domain model") {
//    for {
//      s <- RootKey.stream.take(3).compile.toList
//      mac = Macv1.create(s.head,
//                         CapabilityId("foo"),
//                         CapabilityLocation(new URI("foo")))
//      _ <- Logger[IO].info(s"mac: $mac")
//      _ <- Logger[IO].info(
//        s"Verification: ${mac.verify(s.head, _ => false, Set.empty)}")
//    } yield expect(true)
//  }

  // probably need typeclass for serialization / sig calculation
  case class Mac(location: CapabilityLocation,
                 id: CapabilityId,
                 caveats: List[Caveat], // head is latest
                 code: MessageAuthenticationCode) {

    private implicit def toJavaMacaroon(mac: Mac): Macaroon = {
      ???
//      val caveatPackets = caveats
//        .map {
//          case FirstPartyCaveat(description) =>
//            Vector(new CaveatPacket(CaveatPacket.Type.cid, description))
//          case ThirdPartyCaveat(location, verificationKeyIdentifier, id) =>
//            Vector(
//              new CaveatPacket(CaveatPacket.Type.cid, id.value),
//              new CaveatPacket(CaveatPacket.Type.vid,
//                               verificationKeyIdentifier.value),
//              new CaveatPacket(CaveatPacket.Type.cl, location.value.toString)
//            )
//        }
//        .toVector
//        .reverse
//        .flatten
//      new Macaroon(location.value, id.value, code.value, caveatPackets.toArray)
    }

    def prepareForRequest(dischargeCapability: Capability): Capability = ???

    def addFirstPartyCaveat(caveat: Caveat): Capability = ???

    def addThirdPartyCaveat(key: RootKey,
                            id: CapabilityId,
                            location: CapabilityLocation): Capability =
      ???

    implicit private def verifierToGeneralCaveatVerifier(
        verifier: Verifier): GeneralCaveatVerifier =
      (caveat: String) => verifier(FirstPartyCaveat(caveat))

    def verify(key: RootKey,
               verifier: Verifier,
               discharges: Set[Mac]): VerificationResult =
      new MacaroonsVerifier(this)
        .satisfyGeneral(verifier)
        .pipe(discharges.foldLeft(_)((w, m) => w.satisfy3rdParty(m)))
        .pipe(v => Try(v.assertIsValid(key.value))) match {
        case Success(())                                 => Valid
        case Failure(_: MacaroonValidationException)     => SimpleInvalid
        case Failure(e: GeneralSecurityRuntimeException) => throw e
      }
    // be able to log from verifier? or use debugger?
    // or just await what kind of troubleshooting I want to do in practice?
  }
//  object Macv1 extends CapabilityFactory[Mac] {
//    override def create(key: RootKey,
//                        id: CapabilityId,
//                        location: CapabilityLocation): Mac = {
//      val code = new MacaroonsBuilder(location.value.toString,
//                                      key.value,
//                                      id.value).getMacaroon.signature
//        .pipe(BinHex.hex2bin)
//        .pipe(MessageAuthenticationCode)
//      Mac(location, id, List.empty, code)
//    }
//  }

  case class MessageAuthenticationCode(value: Array[Byte])

  case class VerificationKeyIdentifier(value: Array[Byte])

  sealed trait Caveat
  case class FirstPartyCaveat(description: String) extends Caveat
  case class ThirdPartyCaveat(
      location: CapabilityLocation,
      verificationKeyIdentifier: VerificationKeyIdentifier,
      id: CapabilityId)
      extends Caveat

  // A is a set of true propositions / equiv to a fn: proposition -> boolean
  type Verifier = FirstPartyCaveat => Boolean
  // model verifiers as functions, compose with short circuit true. monoids?
  implicit object VerifierMonoid extends Monoid[Verifier] {
    override def empty: Verifier = _ => false
    override def combine(x: Verifier, y: Verifier): Verifier = c => x(c) || y(c)
  }

  case class RootKey private (value: Array[Byte])
  object RootKey {
    def stream[F[_]: Sync]: Stream[F, RootKey] =
      for {
        m <- Stream.eval[F, ManagedRandom](Sync[F].delay(new ManagedRandom {}))
        k <- Stream
          .eval[F, Array[Byte]](
            Sync[F].delay(new Array[Byte](32).tap(m.nextBytes)))
          .repeat
      } yield RootKey(k)
  }

  sealed trait VerificationResult
  case object Valid extends VerificationResult
  case object SimpleInvalid extends VerificationResult
  case class Invalid(macaroon: Macaroon, message: String)
      extends VerificationResult

  case object Verifier {
    def apply(macaroon: Macaroon, key: RootKey) =
      new MacaroonsVerifier(macaroon)
        .satisfyExact("account = 123")
        .isValid(key.value)

    def x[M[_], E >: GeneralSecurityRuntimeException <: Throwable](
        verifier: MacaroonsVerifier,
        key: RootKey)(implicit M: MonadError[M, E]): M[VerificationResult] =
      Try(verifier.assertIsValid(key.value)) match {
        case Success(()) => M.pure(Valid)
        case Failure(e: MacaroonValidationException) =>
          M.pure(Invalid(e.getMacaroon, e.getMessage))
        case Failure(e: GeneralSecurityRuntimeException) => M.raiseError(e)
      }
  }

  case class CapabilityId(value: String)
  case class CapabilityLocation(value: URI)

//  trait Caveat {
//    def description: String
//  }
//  case class Caveat(description: String)

//  trait Verifier {
//    def verify(caveat: Caveat): Either[String, Unit]
//  }

  trait Capability {
    def prepareForRequest(dischargeCapability: Capability): Capability
    def addFirstPartyCaveat(caveat: Caveat): Capability
    def addThirdPartyCaveat(key: RootKey,
                            id: CapabilityId,
                            location: CapabilityLocation): Capability
    def verify(key: RootKey,
               verifiers: Set[Verifier],
               discharges: Set[Capability]): VerificationResult
  }
  trait CapabilityFactory[C <: Capability] {
    def create(key: RootKey, id: CapabilityId, location: CapabilityLocation): C
  }

//  trait MacaroonService[F[_], RootKey, Id, Macaroon, Location, Caveat] {
//    def create(key: RootKey, id: Id, location: Location): F[Macaroon]
//    def prepareForRequest(a: Macaroon, b: Macaroon): F[Macaroon] // monoid?
//    def addFirstPartyCaveat(macaroon: Macaroon, caveat: Caveat): F[Macaroon]
//    def addThirdPartyCaveat(macaroon: Macaroon,
//                            caveatKey: RootKey,
//                            caveatId: Id,
//                            caveatLocation: Location): F[Macaroon]
////    def verify(macaroon: Macaroon) //??
//  }

//  object MacaroonMonoid extends Monoid[Macaroon] {
//    override def empty: Macaroon = ???
//
//    override def combine(x: Macaroon, y: Macaroon): Macaroon = ???
//  }
}
