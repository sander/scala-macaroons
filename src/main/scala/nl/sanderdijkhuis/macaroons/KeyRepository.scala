package nl.sanderdijkhuis.macaroons

import cats.effect._
import cats.effect.concurrent.Ref
import cats.implicits._
import scodec.bits.ByteVector
import tsec.common.SecureRandomId

trait KeyRepository[F[_]] {

  def protectRootKey(rootKey: RootKey): F[Identifier]

  def protectRootKeyAndPredicate(rootKey: RootKey,
                                 identifier: Identifier): F[Identifier]

  def restoreRootKey(identifier: Identifier): F[RootKey]

  def restoreRootKeyAndPredicate(
      identifier: Identifier): F[(RootKey, Predicate)]

}

object KeyRepository {

//  def apply[F[_]](implicit repository: KeyRepository[F]): KeyRepository[F] =
//    repository

  trait Live[F[_]] extends KeyRepository[F] {}

  def apply[F[_]: Sync]: KeyRepository[F] = new Live[F] {

    private def generateIdentifier(): F[Identifier] =
      SecureRandomId.Interactive.generateF.flatMap(b =>
        Sync[F].delay(Identifier.from(ByteVector(b.getBytes)).get))

    override def protectRootKey(rootKey: RootKey): F[Identifier] =
      generateIdentifier() // TODO

    override def protectRootKeyAndPredicate(
        rootKey: RootKey,
        identifier: Identifier): F[Identifier] = ???

    override def restoreRootKey(identifier: Identifier): F[RootKey] = ???

    override def restoreRootKeyAndPredicate(
        identifier: Identifier): F[(RootKey, Predicate)] = ???
  }
}
