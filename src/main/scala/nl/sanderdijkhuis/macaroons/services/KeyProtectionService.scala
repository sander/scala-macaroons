package nl.sanderdijkhuis.macaroons.services

import cats.effect._
import cats.effect.concurrent.Ref
import cats.implicits._
import scodec.bits.ByteVector
import eu.timepit.refined._
import eu.timepit.refined.collection._
import nl.sanderdijkhuis.macaroons.{Identifier, Predicate, RootKey}
import tsec.common.SecureRandomId

import scala.collection.immutable.Map

trait KeyProtectionService[F[_]] {

  def protectRootKey(rootKey: RootKey): F[Identifier]

  def protectRootKeyAndPredicate(rootKey: RootKey,
                                 predicate: Predicate): F[Identifier]

  def restoreRootKey(identifier: Identifier): F[Option[RootKey]]

  def restoreRootKeyAndPredicate(
      identifier: Identifier): F[Option[(RootKey, Predicate)]]
}

object KeyProtectionService {

  trait Live[F[_]] extends KeyProtectionService[F] {}

  trait InMemory[F[_]] extends KeyProtectionService[F] {

    import nl.sanderdijkhuis.macaroons._

    implicit val sync: Sync[F]
    val rootKeys: Ref[F, Map[Identifier, RootKey]]
    val rootKeysAndPredicates: Ref[F, Map[Identifier, (RootKey, Predicate)]]

    private def generateIdentifier(): F[Identifier] =
      for {
        raw <- SecureRandomId.Interactive.generateF
        value <- Sync[F].fromEither(
          refineV[NonEmpty](ByteVector(raw.getBytes)).leftMap(new Throwable(_)))
      } yield Identifier(value)

    override def protectRootKey(rootKey: RootKey): F[Identifier] =
      for {
        id <- generateIdentifier()
        _ <- rootKeys.modify(m => (m + (id -> rootKey), ()))
      } yield id

    override def protectRootKeyAndPredicate(
        rootKey: RootKey,
        predicate: Predicate): F[Identifier] =
      for {
        id <- generateIdentifier()
        _ <- rootKeysAndPredicates.modify(m =>
          (m + (id -> (rootKey, predicate)), ()))
      } yield id

    override def restoreRootKey(identifier: Identifier): F[Option[RootKey]] =
      rootKeys.get.map(m => m.get(identifier))

    override def restoreRootKeyAndPredicate(
        identifier: Identifier): F[Option[(RootKey, Predicate)]] =
      rootKeysAndPredicates.get.map(_.get(identifier))
  }

  def inMemory[F[_]](implicit F: Sync[F]): F[KeyProtectionService[F]] =
    (Ref.of[F, Map[Identifier, RootKey]](Map.empty),
     Ref.of[F, Map[Identifier, (RootKey, Predicate)]](Map.empty))
      .mapN((r1, r2) =>
        new InMemory[F] {
          override implicit val sync: Sync[F] = F
          override val rootKeys: Ref[F, Map[Identifier, RootKey]] = r1
          override val rootKeysAndPredicates
            : Ref[F, Map[Identifier, (RootKey, Predicate)]] = r2
      })
}
