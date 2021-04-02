package nl.sanderdijkhuis.macaroons.services

import cats.effect._
import cats.effect.concurrent.Ref
import cats.implicits._
import scodec.bits.ByteVector
import eu.timepit.refined._
import eu.timepit.refined.collection._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.types.bytes._
import tsec.common.SecureRandomId

import scala.collection.immutable.Map

/**
  * Represents the capability to protect keys, by wrapping or by secure storage.
  */
trait KeyProtectionService[F[_], RootKey] {

  def protectRootKey(rootKey: RootKey): F[Identifier]

  def protectRootKeyAndPredicate(rootKey: RootKey,
                                 predicate: Predicate): F[Identifier]

  def restoreRootKey(identifier: Identifier): F[Option[RootKey]]

  def restoreRootKeyAndPredicate(
      identifier: Identifier): F[Option[(RootKey, Predicate)]]
}

object KeyProtectionService {

  trait InMemory[F[_], RootKey] extends KeyProtectionService[F, RootKey] {

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

  def inMemory[F[_], RootKey](
      implicit F: Sync[F]): F[KeyProtectionService[F, RootKey]] =
    (Ref.of[F, Map[Identifier, RootKey]](Map.empty),
     Ref.of[F, Map[Identifier, (RootKey, Predicate)]](Map.empty))
      .mapN((r1, r2) =>
        new InMemory[F, RootKey] {
          override implicit val sync: Sync[F] = F
          override val rootKeys: Ref[F, Map[Identifier, RootKey]] = r1
          override val rootKeysAndPredicates
            : Ref[F, Map[Identifier, (RootKey, Predicate)]] = r2
      })
}
