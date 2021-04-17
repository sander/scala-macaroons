package nl.sanderdijkhuis.macaroons.integration.example.domain

import io.estatico.newtype.macros.newtype
import nl.sanderdijkhuis.macaroons.domain.macaroon.{Authority, Macaroon}

import java.util.UUID
import scala.language.implicitConversions

object authentication {

  @newtype
  case class SessionId(value: UUID)

  @newtype
  case class Challenge(value: String)

  @newtype
  case class Proof(value: Array[Byte])

  @newtype
  case class PrincipalId(id: UUID)

  sealed trait SessionStatus
  case class Initial() extends SessionStatus
//  case class Authenticated(principalId: PrincipalId) extends SessionStatus
  case class Terminated() extends SessionStatus

  @newtype
  case class ProcessId(value: UUID)

  sealed trait AuthenticationState

  object AuthenticationState {

    case class Challenged(sessionId: SessionId, challenge: Challenge)
        extends AuthenticationState
    case class ChallengeExpired() extends AuthenticationState
    case class Authenticated()    extends AuthenticationState
  }

  sealed trait AuthenticationError

  object AuthenticationError {
    case class Unauthorized() extends AuthenticationError
  }

  type ChallengeCommandHandler[F[_]] =
    () => F[(Macaroon with Authority, SessionId, ProcessId, Challenge)]

  type AuthenticationStateQueryHandler[F[_]] = (SessionId, ProcessId) => (
      Macaroon with Authority) => F[AuthenticationState]

  type AuthenticateCommandHandler[F[_]] = (Challenge, PrincipalId) => F[Unit]

}
