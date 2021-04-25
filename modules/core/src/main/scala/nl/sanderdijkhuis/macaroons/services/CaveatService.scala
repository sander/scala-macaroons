package nl.sanderdijkhuis.macaroons.services

import nl.sanderdijkhuis.macaroons.domain._

import cats._
import cats.data._
import cats.implicits._

trait CaveatService[F[_], Context] {

  def attenuate(predicate: Predicate): F[Unit]

  def confine(context: Context, predicate: Predicate): F[Identifier]
}

object CaveatService {

  type StatefulCaveatService[F[_], RootKey] =
    CaveatService[Transformation[F, *], Context[F, RootKey]]

  def make[F[_]: Monad, RootKey, AuthCipher](
      macaroonService: MacaroonService[F, RootKey],
      generateKey: F[RootKey]): StatefulCaveatService[F, RootKey] =
    new CaveatService[Transformation[F, *], Context[F, RootKey]] {

      override def attenuate(predicate: Predicate): Transformation[F, Unit] =
        StateT(macaroonService.addFirstPartyCaveat(_, predicate.identifier).map(
          (_, ())))

      override def confine(
          context: Context[F, RootKey],
          predicate: Predicate): Transformation[F, Identifier] =
        StateT(m =>
          for {
            rootKey <- generateKey
            cId     <- context.prepare(rootKey, predicate)
            m <- macaroonService
              .addThirdPartyCaveat(m, rootKey, cId, context.maybeLocation)
          } yield (m, cId))
    }
}
