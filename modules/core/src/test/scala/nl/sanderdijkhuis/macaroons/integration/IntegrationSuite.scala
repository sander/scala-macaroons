package nl.sanderdijkhuis.macaroons.integration

import cats.data._
import cats.effect._
import cats.implicits._
import cats.tagless.Derive
import cats.{~>, Applicative}
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import monocle.Lens
import monocle.macros.GenLens
import munit.FunSuite
import nl.sanderdijkhuis.macaroons.cryptography.util._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.modules.{Assertions, Discharges, Macaroons}
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import nl.sanderdijkhuis.macaroons.services.MacaroonService.RootKey
import tsec.cipher.symmetric.Encryptor
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XChaCha20Poly1305}
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

class IntegrationSuite extends FunSuite {

  import TestData._

  type E    = Throwable
  type F[A] = Either[E, A]

  test("example from paper") {
    val C = macaroons.caveats
    val program: StateT[F, TestState, Boolean] = for {
      m_ts <- ts.assert()
      m_ts <-
      (C.attenuate(chunkInRange) *> C.attenuate(opInReadWrite) *>
        C.attenuate(timeBefore3pm)).runS(m_ts)
      (m_fs, cid) <-
      (C.confine(asEndpoint, userIsBob) <* C.attenuate(chunkIs235) <*
        C.attenuate(operationIsRead)).run(m_ts)
      _           <- as.getPredicate(cid).flatMapF(handleError("no predicate"))
      m_as        <- as.discharge(cid).flatMapF(handleError("no discharge"))
      m_as        <- (C.attenuate(timeBefore9am) *> C.attenuate(ipMatch)).runS(m_as)
      m_as_sealed <- macaroons.binding.bind(m_fs, m_as)
      result      <- ts.verify(m_fs, tsVerifier, Set(m_as_sealed))
    } yield result
    assert(program.runA(TestState()).contains(true))
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

    val chunkInRange    = Predicate.from("chunk in {100...500}")
    val opInReadWrite   = Predicate.from("op in {read, write}")
    val timeBefore3pm   = Predicate.from("time < 5/1/13 3pm")
    val userIsBob       = Predicate.from("user = bob")
    val chunkIs235      = Predicate.from("chunk = 235")
    val operationIsRead = Predicate.from("operation = read")
    val timeBefore9am   = Predicate.from("time < 5/1/13 9am")
    val ipMatch         = Predicate.from("ip = 192.0.32.7")

    val tsVerifier = Set(
      chunkInRange,
      opInReadWrite,
      timeBefore3pm,
      chunkIs235,
      operationIsRead,
      timeBefore9am,
      ipMatch)

    case class TestState(
        ts: PrincipalState = PrincipalState(),
        fs: PrincipalState = PrincipalState(),
        as: PrincipalState = PrincipalState(),
        nextInt: Int = 0)

    val asEndpoint = Context[StateT[F, TestState, *], RootKey](
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

    private def functorK[F[_]: Applicative, S]: F ~> StateT[F, S, *] =
      λ[F ~> StateT[F, S, *]](s => StateT.liftF(s))

    val macaroons: Macaroons[StateT[F, TestState, *]] = {
      type G[A] = StateT[F, TestState, A]
      implicit val s: SymmetricKeyGen[G, HMACSHA256, MacSigningKey] = Derive
        .functorK[SymmetricKeyGen[*[_], HMACSHA256, MacSigningKey]].mapK[F, G](
          implicitly[SymmetricKeyGen[F, HMACSHA256, MacSigningKey]])(functorK)
      implicit val e: Encryptor[G, XChaCha20Poly1305, BouncySecretKey] = Derive
        .functorK[Encryptor[*[_], XChaCha20Poly1305, BouncySecretKey]]
        .mapK[F, G](encryptor[F, E])(functorK)
      Macaroons.make[G, E](StateT.liftF(unsafeGenerateIv))
    }

    private def unsafeDischarges(
        id: PrincipalId,
        maybeLocation: Option[Location])
        : Discharges[StateT[F, TestState, *]] = {
      type G[A] = StateT[F, TestState, A]
      Discharges
        .make[G, E](maybeLocation)(macaroons, dischargeKeyRepository(id))
    }

    private def unsafeAssertions(
        id: PrincipalId,
        maybeLocation: Option[Location])
        : Assertions[StateT[F, TestState, *]] = {
      type G[A] = StateT[F, TestState, A]
      Assertions.make[G, E](
        maybeLocation,
        macaroons,
        rootKeyRepository(id),
        StateT.liftF(unsafeGenerateKey))
    }

    val ts =
      unsafeAssertions(GenLens[TestState](_.ts), targetServiceLocation.some)
        .service

    val fs =
      unsafeDischarges(GenLens[TestState](_.fs), forumServiceLocation.some)
        .service

    val as = unsafeDischarges(
      GenLens[TestState](_.as),
      authenticationServiceLocation.some).service
  }
}
