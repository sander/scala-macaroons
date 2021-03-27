package nl.sanderdijkhuis.macaroons

import cats.effect._
import cats.effect.concurrent.Ref
import cats.implicits._
import scodec.bits.ByteVector
import tsec.common.SecureRandomId
import eu.timepit.refined._
import eu.timepit.refined.api.RefType.refinedRefType
import eu.timepit.refined.auto._
import eu.timepit.refined.numeric._
import eu.timepit.refined.api.{Failed, Passed, RefType, Refined, Validate}
import eu.timepit.refined.boolean._
import eu.timepit.refined.char._
import eu.timepit.refined.collection._
import eu.timepit.refined.generic._
import eu.timepit.refined.string._
import eu.timepit.refined.scodec.byteVector._
import eu.timepit.refined.types.string.NonEmptyString

import scala.collection.immutable.Map

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

  trait InMemory[F[_]] extends KeyRepository[F] {

    implicit val sync: Sync[F]
    val rootKeys: Ref[F, Map[Identifier, RootKey]]

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
        identifier: Identifier): F[Identifier] = ???

    override def restoreRootKey(identifier: Identifier): F[RootKey] =
      rootKeys.get.flatMap(m =>
        Sync[F].fromOption(m.get(identifier), new Throwable("not found")))

    override def restoreRootKeyAndPredicate(
        identifier: Identifier): F[(RootKey, Predicate)] = ???
  }

  def inMemory[F[_]](implicit F: Sync[F]): F[KeyRepository[F]] =
    Ref
      .of[F, Map[Identifier, RootKey]](Map.empty)
      .map(r =>
        new InMemory[F] {
          override implicit val sync: Sync[F] = F
          override val rootKeys: Ref[F, Map[Identifier, RootKey]] = r
      })

//  def apply[F[_]: Sync]: KeyRepository[F] = new Live[F] {
//
//    private def generateIdentifier(): F[Identifier] =
//      for {
//        raw <- SecureRandomId.Interactive.generateF
//        value <- Sync[F].fromEither(
//          refineV[NonEmpty](ByteVector(raw.getBytes)).leftMap(new Throwable(_)))
//      } yield Identifier(value)
//
//    override def protectRootKey(rootKey: RootKey): F[Identifier] =
//      generateIdentifier() // TODO
//
//    override def protectRootKeyAndPredicate(
//        rootKey: RootKey,
//        identifier: Identifier): F[Identifier] = ???
//
//    override def restoreRootKey(identifier: Identifier): F[RootKey] = ???
//
//    override def restoreRootKeyAndPredicate(
//        identifier: Identifier): F[(RootKey, Predicate)] = ???
//  }
}
