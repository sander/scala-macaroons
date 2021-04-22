package nl.sanderdijkhuis.macaroons.integration

import cats.data._
import cats.effect._
import cats.implicits._
import cats.tagless.Derive
import cats.{~>, Applicative}
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import munit.FunSuite
import nl.sanderdijkhuis.macaroons.cryptography._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.modules.Macaroons
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
    import macaroons.caveats._
    import macaroons.service._
    val txAtTs = attenuate(chunkInRange) *> attenuate(opInReadWrite) *>
      attenuate(timeBefore3pm)
    val txAtFs = confine(asEndpoint, userIsBob) <* attenuate(chunkIs235) <*
      attenuate(operationIsRead)
    val txAtAs = attenuate(timeBefore9am) *> attenuate(ipMatch)
    val program: StateT[F, TestState, Boolean] = for {
      mk         <- key
      mTS        <- mint(mId, mk, Some(targetServiceLocation)) >>= txAtTs.runS
      (mFS, cid) <- txAtFs.run(mTS)
      dk         <- dischargeKey
      mAS        <- mint(cid, dk, asEndpoint.maybeLocation) >>= txAtAs.runS
      mASs       <- bind(mFS, mAS)
      result     <- verify(mFS, mk, tsVerifier, Set(mASs))
    } yield result
    assert(program.runA(TestState()).contains(true))
  }

  //noinspection TypeAnnotation
  private object TestData {

    def dischargeKey =
      StateT.inspectF((s: TestState) =>
        s.dischargeKey.toRight(new Throwable("not found")))

    val targetServiceLocation = Location("https://target.example/")

    private val authenticationServiceLocation =
      Location("https://authentication.example/")

    val mId = Identifier.from("m1")

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

    case class TestState(dischargeKey: Option[RootKey] = None)

    val asEndpoint = Context[StateT[F, TestState, *], RootKey](
      Some(authenticationServiceLocation),
      (v, w) =>
        StateT((s: TestState) =>
          (s.copy(dischargeKey = Some(v)), Identifier.from("dm")).asRight))

    def key =
      StateT.liftF[F, TestState, MacSigningKey[HMACSHA256]](
        HMACSHA256.generateKey[IO].attempt.unsafeRunSync())

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
  }
}
