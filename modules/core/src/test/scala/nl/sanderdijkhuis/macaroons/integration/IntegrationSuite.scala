package nl.sanderdijkhuis.macaroons.integration

import cats.data._
import cats.effect._
import cats.implicits._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import monocle.Lens
import monocle.macros.GenLens
import munit.FunSuite
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.domain.verification.{
  VerificationResult, Verified
}
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import nl.sanderdijkhuis.macaroons.services.MacaroonService.RootKey
import nl.sanderdijkhuis.macaroons.services.{MacaroonService, PrincipalService}
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.HMACSHA256

class IntegrationSuite extends FunSuite {

  import TestData._

  type E    = Throwable
  type F[A] = Either[E, A]

  test("example from paper") {
    val program: StateT[F, TestState, VerificationResult] = for {
      m_ts <- ts.assert()
      m_ts <- ts.addFirstPartyCaveat(m_ts, chunkInRange)
      m_ts <- ts.addFirstPartyCaveat(m_ts, opInReadWrite)
      m_ts <- ts.addFirstPartyCaveat(m_ts, timeBefore3pm)
      (m_fs, cid) <- fs
        .addThirdPartyCaveat(m_ts, Predicate(userIsBob), asEndpoint)
      m_fs        <- fs.addFirstPartyCaveat(m_fs, chunkIs235)
      m_fs        <- fs.addFirstPartyCaveat(m_fs, operationIsRead)
      _           <- as.getPredicate(cid).flatMapF(handleError("no predicate"))
      m_as        <- as.discharge(cid).flatMapF(handleError("no discharge"))
      m_as        <- as.addFirstPartyCaveat(m_as, timeBefore9am)
      m_as        <- as.addFirstPartyCaveat(m_as, ipMatch)
      m_as_sealed <- StateT.liftF(MacaroonService[F, E].bind(m_fs, m_as))
      result      <- ts.verify(m_fs, tsVerifier, Set(m_as_sealed))
    } yield result
    assert(program.runA(TestState()).contains(Verified))
  }

  //noinspection TypeAnnotation
  private object TestData {

    def handleError[A](s: String)(a: Option[A]): Either[E, A] =
      a.toRight(new Throwable(s))

    private val generateIdInState: State[TestState, Identifier] = {
      val generate = State((i: Int) => (i + 1, i))
      val lens     = GenLens[TestState](_.nextInt)
      val generateInState = State { (t: TestState) =>
        val (state, i) = generate.run(lens.get(t)).value
        (lens.replace(state)(t), i)
      }
      def identifier(i: Int) =
        Identifier.from(refineV[NonEmpty].unsafeFrom(i.toString))
      generateInState.map(identifier)
    }

    private val targetServiceLocation = Location("https://target.example/")
    private val forumServiceLocation  = Location("https://forum.example/")

    private val authenticationServiceLocation =
      Location("https://authentication.example/")

    val chunkInRange    = Identifier.from("chunk in {100...500}")
    val opInReadWrite   = Identifier.from("op in {read, write}")
    val timeBefore3pm   = Identifier.from("time < 5/1/13 3pm")
    val userIsBob       = Identifier.from("user = bob")
    val chunkIs235      = Identifier.from("chunk = 235")
    val operationIsRead = Identifier.from("operation = read")
    val timeBefore9am   = Identifier.from("time < 5/1/13 9am")
    val ipMatch         = Identifier.from("ip = 192.0.32.7")

    def tsVerifier(p: Identifier) =
      VerificationResult.from(
        Set(
          chunkInRange,
          opInReadWrite,
          timeBefore3pm,
          chunkIs235,
          operationIsRead,
          timeBefore9am,
          ipMatch).contains(p))

    case class TestState(
        ts: PrincipalState = PrincipalState(),
        fs: PrincipalState = PrincipalState(),
        as: PrincipalState = PrincipalState(),
        nextInt: Int = 0)

    val ts =
      unsafePrincipal(GenLens[TestState](_.ts), targetServiceLocation.some)

    val fs =
      unsafePrincipal(GenLens[TestState](_.fs), forumServiceLocation.some)

    val as = unsafePrincipal(
      GenLens[TestState](_.as),
      authenticationServiceLocation.some)

    val asEndpoint = Endpoint[StateT[F, TestState, *], RootKey](
      Some(authenticationServiceLocation),
      (v, w) => dischargeKeyRepository(GenLens[TestState](_.as)).protect(v, w))

    case class PrincipalState(
        rootKeys: Map[Identifier, RootKey] = Map.empty,
        dischargeKeys: Map[Identifier, (RootKey, Predicate)] = Map.empty)

    private type PrincipalId = Lens[TestState, PrincipalState]

    private def rootKeyRepository(id: PrincipalId) =
      KeyRepository.inMemoryF[F, TestState, Identifier, RootKey](
        id.andThen(GenLens[PrincipalState](_.rootKeys)),
        generateIdInState)

    private def dischargeKeyRepository(id: PrincipalId) =
      KeyRepository.inMemoryF[F, TestState, Identifier, (RootKey, Predicate)](
        id.andThen(GenLens[PrincipalState](_.dischargeKeys)),
        generateIdInState)

    private def unsafeGenerateKey =
      HMACSHA256.generateKey[IO].attempt.unsafeRunSync()

    private def unsafeGenerateIv =
      XChaCha20Poly1305.defaultIvGen[IO].genIv.attempt.unsafeRunSync()

    private def unsafePrincipal(
        id: PrincipalId,
        maybeLocation: Option[Location]) =
      PrincipalService.make[StateT[F, TestState, *], E](maybeLocation)(
        rootKeyRepository(id),
        dischargeKeyRepository(id),
        StateT.liftF(unsafeGenerateKey),
        StateT.liftF(unsafeGenerateIv))
  }
}
