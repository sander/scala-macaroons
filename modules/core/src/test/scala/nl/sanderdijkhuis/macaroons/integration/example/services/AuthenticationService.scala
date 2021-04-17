package nl.sanderdijkhuis.macaroons.integration.example.services

import cats.implicits._
import cats.{Monad, MonadError}
import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.domain.macaroon.{Endpoint, Identifier}
import nl.sanderdijkhuis.macaroons.domain.verification.{
  VerificationFailed, VerificationResult, Verified, Verifier, VerifierMonoid
}
import nl.sanderdijkhuis.macaroons.integration.example.domain.authentication.AuthenticationState.Challenged
import nl.sanderdijkhuis.macaroons.integration.example.domain.authentication._
import nl.sanderdijkhuis.macaroons.integration.example.effects.{Time, UUIDs}
import nl.sanderdijkhuis.macaroons.services.{MacaroonService, PrincipalService}
import scodec.codecs.utf8

import java.time.Instant

object AuthenticationService {

  def challenge[F[_]: Monad: Time: UUIDs](
      principal: PrincipalService[F, Endpoint[F, MacaroonService.RootKey]],
      startSession: F[SessionId],
      generateChallenge: F[Challenge],
      saveState: (ProcessId, AuthenticationState) => F[Unit])
      : ChallengeCommandHandler[F] =
    () =>
      for {
        s <- startSession
        p <- processId
        c <- generateChallenge
        t <- afterMinutes(5)
        m <- principal.assert()
        m <- principal.addFirstPartyCaveat(m, sessionIdEquals(s))
        m <- principal.addFirstPartyCaveat(m, processIdEquals(p))
        m <- principal.addFirstPartyCaveat(m, timeBefore(t))
        _ <- saveState(p, AuthenticationState.Challenged(s, c))
      } yield (m, s, p, c)

  private def verifyTimeBefore(now: Instant): Verifier =
    (identifier: Identifier) => {
      val prefix          = utf8.encode("time < ").require.bytes
      val (before, after) = identifier.value.value.splitAt(prefix.size)
      VerificationResult.from(
        before === prefix &&
          (utf8.decode(after.bits).require.value.toLong < now.toEpochMilli))
    }

  def getState[F[_]: Monad: Time](
      principal: PrincipalService[F, Endpoint[F, MacaroonService.RootKey]],
      lookup: ProcessId => F[AuthenticationState])(implicit
      F: MonadError[F, AuthenticationError])
      : AuthenticationStateQueryHandler[F] =
    (sessionId, processId) =>
      macaroon => {
        val predicates =
          Set(sessionIdEquals(sessionId), processIdEquals(processId))
        val verifier: Verifier = (identifier: Identifier) =>
          VerificationResult.from(predicates.contains(identifier))
        for {
          now <- Time[F].get
          result <- principal.verify(
            macaroon,
            verifier.combine(verifyTimeBefore(now)),
            Set.empty)
          r <- result match {
            case Verified => for { s <- lookup(processId) } yield s
            case VerificationFailed => F
                .raiseError(AuthenticationError.Unauthorized())
          }
        } yield r
      }

  def authenticate[F[_]](
      find: Challenge => F[ProcessId],
      lookup: ProcessId => F[AuthenticationState],
      update: (ProcessId, AuthenticationState) => F[Unit],
      updateSession: (SessionId, PrincipalId) => F[Unit])(implicit
      F: MonadError[F, AuthenticationError]): AuthenticateCommandHandler[F] =
    (challenge, principalId) =>
      for {
        p <- find(challenge)
        s <- lookup(p).flatMap {
          case Challenged(s, c) if c == challenge => s.pure[F]
          case _                                  => F.raiseError[SessionId](AuthenticationError.Unauthorized())
        }
        _ <- update(p, AuthenticationState.Authenticated())
        _ <- updateSession(s, principalId)
      } yield ()

  private def sessionIdEquals(sessionId: SessionId): Identifier =
    Identifier.from(
      refineV[NonEmpty].unsafeFrom(s"session = ${sessionId.value.toString}"))

  private def processIdEquals(processId: ProcessId): Identifier =
    Identifier.from(
      refineV[NonEmpty].unsafeFrom(s"process = ${processId.value.toString}"))

  private def timeBefore(instant: Instant): Identifier =
    Identifier
      .from(refineV[NonEmpty].unsafeFrom(s"time < ${instant.toEpochMilli}"))

  private def processId[F[_]: UUIDs: Monad]: F[ProcessId] =
    UUIDs[F].make().map(ProcessId.apply)

  //noinspection SameParameterValue
  private def afterMinutes[F[_]: Time: Monad](minutes: Int): F[Instant] =
    Time[F].get
      .map(t => Instant.ofEpochMilli(t.toEpochMilli + minutes * 60 * 1000))
}
