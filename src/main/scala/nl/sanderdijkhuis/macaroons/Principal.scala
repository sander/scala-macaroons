package nl.sanderdijkhuis.macaroons

import cats._
import cats.effect._
import cats.implicits._
import scodec.bits.ByteVector

trait Principal[F[_]] {

  def maybeLocation: Option[Location]

  def assert(): F[Macaroon with Authority]
}

object Principal {

  trait NewKeyService[F[_], Key] {
    def generate(): F[Key]
    def protect(key: Key, maybeIdentifier: Option[Identifier]): F[Identifier]
    def recover(identifier: Identifier): F[(Key, Option[Identifier])]
    def authenticate(key: Key, identifier: Identifier): F[Tag]
//    def authenticate(authentication: Authentication,
//                     maybeChallenge: Option[Challenge],
//                     identifier: Identifier): F[Authentication]
    def encrypt(authentication: Tag, key: Key): F[Challenge]
    def decrypt(authentication: Tag, challenge: Challenge): F[Key]
//    def bind(discharging: Authentication,
//             authorizing: Authentication): F[Authentication]
  }

  def assert[F[_]: Monad]()(
      implicit service: NewKeyService[F, RootKey]): F[Macaroon] =
    for {
      rootKey <- service.generate()
      cId <- service.protect(rootKey, None)
      tag <- service.authenticate(rootKey, cId)
    } yield Macaroon(None, cId, Vector.empty, tag)

  case class Live[F[_]: Monad: KeyManagement: KeyRepository](
      override val maybeLocation: Option[Location])
      extends Principal[F] {

    override def assert(): F[Macaroon with Authority] =
      for {
        rootKey <- KeyManagement[F].generateRootKey()
        cId <- KeyRepository[F].protectRootKey(rootKey)
        tag <- KeyManagement[F].authenticateAssertion(rootKey, cId)
      } yield Macaroon(maybeLocation, cId, Vector.empty, tag)
  }

//  case class Live[F[_]: KeyService: Monad: Sync: KeyManagement](
//      override val location: Option[Location])
//      extends Principal[F] {
//
//    override def assert(): F[Macaroon] =
//      for {
//        rootKey <- RootKey.stream.head.compile.lastOrError
//        cId <- KeyService[F].protectAsFirstParty(rootKey)
//      } yield Macaroon.create(rootKey, cId, location)
//  }

  private def create[F[_]: KeyManagement: KeyRepository](
      location: Option[String])(
      implicit F: MonadError[F, Throwable]): F[Principal[F]] =
    for {
      loc <- location match {
        case Some(location) =>
          F.fromOption(Location.from(location),
                        new Throwable("Invalid location"))
            .map(Some(_))
        case None => F.pure(None)
      }
    } yield Live[F](loc)

  def apply[F[_]: Sync: KeyManagement: KeyRepository](
      location: String): F[Principal[F]] = create(Some(location))

  def apply[F[_]: Sync: KeyManagement: KeyRepository](): F[Principal[F]] =
    create(None)
}
