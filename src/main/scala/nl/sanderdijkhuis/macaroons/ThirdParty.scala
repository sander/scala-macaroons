package nl.sanderdijkhuis.macaroons

import cats.{Applicative, Monad}
import cats.implicits._

trait ThirdParty[F[_]] {

  def prepare(rootKey: RootKey, predicate: Predicate): F[Identifier]

  def maybeLocation: F[Option[Location]]
}

object ThirdParty {

  def make[F[_]: Applicative](maybeLoc: Option[Location])(
      f: (RootKey, Predicate) => F[Identifier]): ThirdParty[F] =
    new ThirdParty[F] {

      override def prepare(rootKey: RootKey,
                           predicate: Predicate): F[Identifier] =
        f(rootKey, predicate)

      override def maybeLocation: F[Option[Location]] = maybeLoc.pure[F]
    }
}
