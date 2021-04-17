package nl.sanderdijkhuis.macaroons.integration.example.services

import cats.Monad
import cats.effect.Clock
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon.{Endpoint, Macaroon}
import nl.sanderdijkhuis.macaroons.integration.example.caveats.session.timeBefore
import nl.sanderdijkhuis.macaroons.integration.example.domain.authentication.{
  SessionId, SessionStatus
}
import nl.sanderdijkhuis.macaroons.services.{MacaroonService, PrincipalService}
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

import java.time.Instant
import java.util.concurrent.TimeUnit

object SessionService {

  case class SessionStarted(sessionId: SessionId)

  case class SessionRefreshed(sessionId: SessionId)

  case class SessionTerminated()

//  def start[F[_]: Monad: Clock](
//      principal: PrincipalService[F, Endpoint[F, MacaroonService.RootKey]])()
//      : F[SessionStarted] =
//    for {
//      m <- principal.assert()
//      t <- Clock[F].realTime(TimeUnit.MILLISECONDS)
//        .map(t => new Instant(t + 5 * 60 * 1000))
//      m <- principal.addFirstPartyCaveat(m, timeBefore(t))
//    } yield SessionStarted(SessionId(m))
//
//  def refresh[F[_]: Monad](
//      principalService: PrincipalService[
//        F,
//        Endpoint[F, MacaroonService.RootKey]])(
//      sessionId: SessionId): F[SessionRefreshed] =
//    principalService.verify(sessionId.macaroon)
  // TODO session is mostly used in discharge macaroon, not authority in itself

  //  def queryStatus[F[_]: Monad](
//      principalService: PrincipalService[
//        F,
//        Endpoint[F, MacaroonService.RootKey]])(sessionId: SessionId)(
//      discharges: Set[Macaroon]): F[SessionStatus] = ???

  def terminate[F[_]: Monad](
      principalService: PrincipalService[
        F,
        Endpoint[F, MacaroonService.RootKey]])(): F[SessionTerminated] = ???
}
