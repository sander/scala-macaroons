package nl.sanderdijkhuis.macaroons.integration

import cats.{Monad, MonadError}
import cats.implicits._
import cats.data.{Kleisli, StateT}
import cats.effect.Clock
import io.estatico.newtype.macros.newtype
import munit.FunSuite
import nl.sanderdijkhuis.macaroons.integration.example.domain.authentication.{
  AuthenticateCommandHandler, AuthenticationError, AuthenticationState,
  AuthenticationStateQueryHandler, ChallengeCommandHandler, PrincipalId
}
import nl.sanderdijkhuis.macaroons.integration.example.effects.{Time, UUIDs}
import nl.sanderdijkhuis.macaroons.integration.example.services.AuthenticationService
import shapeless.{:+:, CNil}

import java.time.Instant
import java.util.UUID
import scala.concurrent.duration.TimeUnit
import scala.language.implicitConversions

class ExampleApplication extends FunSuite {
  case class TestState(now: Instant, nextUUID: UUID)

  sealed trait TestError

  object TestError {
    case class Authentication(value: AuthenticationError) extends TestError
    case class UnexpectedStateError()                     extends TestError
  }

  type Effect[A] = StateT[Either[TestError, *], TestState, A]

//  implicit val clock: Clock[F] = new Clock[F] {
//    override def realTime(unit: TimeUnit): F[Long] = ???
//
//    override def monotonic(unit: TimeUnit): F[Long] = ???
//  }
  implicit val time: Time[Effect] =
    () => StateT(s => (s, s.now).pure[Either[TestError, *]])

  implicit val uuids: UUIDs[Effect] = () =>
    StateT(s =>
      (s.copy(nextUUID = UUID.randomUUID()), s.nextUUID)
        .pure[Either[TestError, *]])

  test("authentication service") {
    val alice =
      PrincipalId(UUID.fromString("fc061d1b-61cd-46f5-9e6e-ee50141af0c0"))
    val challenge: ChallengeCommandHandler[F] = AuthenticationService
      .challenge[Effect]()
    val query: AuthenticationStateQueryHandler[F]   = ???
    val authenticate: AuthenticateCommandHandler[F] = ???
    def program[F[_]](implicit F: MonadError[F, TestError]): F[Unit] =
      for {
        (mac, sid, pid, ch) <- challenge()
        _ <- query(sid, pid)(mac).flatMap {
          case AuthenticationState.Challenged(_, _) => F.pure(())
          case _                                    => F.raiseError[Unit](TestError.UnexpectedStateError())
        }
        _ <- authenticate(ch, alice)
        _ <- query(sid, pid)(mac).flatMap {
          case AuthenticationState.Authenticated() => F.pure(())
          case _                                   => F.raiseError[Unit](TestError.UnexpectedStateError())
        }
      } yield ()
    assert(
      program[Effect](
        AuthenticationService.challenge[Effect](),
        AuthenticationService.getState[Effect],
        AuthenticationService.authenticate[Effect])
        .runA(TestState(Instant.now(), UUID.randomUUID())).contains(()))
//    assert(true)
  }
}
