package nl.sanderdijkhuis.macaroons

import cats._
import cats.effect._
import cats.implicits._
import scodec.bits.ByteVector

trait Principal[F[_]] {

//  def maybeLocation: Option[Location]

  def assert(): F[Macaroon with Authority]

  def addThirdPartyCaveat(
      macaroon: Macaroon with Authority,
      identifier: Identifier,
      thirdParty: ThirdParty[F],
      maybeLocation: Option[Location]): F[Macaroon with Authority]
}

object Principal {

  case class Live[F[_]: Sync](maybeLocation: Option[Location])(
      keyManagement: KeyManagement[F],
      keyRepository: KeyRepository[F],
      macaroonService: MacaroonService[F])
      extends Principal[F] {

    override def assert(): F[Macaroon with Authority] =
      for {
        rootKey <- keyManagement.generateRootKey()
        cId <- keyRepository.protectRootKey(rootKey)
        m <- macaroonService.generate(cId, rootKey, maybeLocation)
      } yield m

    override def addThirdPartyCaveat(
        macaroon: Macaroon with Authority,
        identifier: Identifier,
        thirdParty: ThirdParty[F],
        maybeLocation: Option[Location]): F[Macaroon with Authority] =
      for {
        rootKey <- keyManagement.generateRootKey()
        cId <- thirdParty.prepare(rootKey, identifier)
        m <- macaroonService.addThirdPartyCaveat(macaroon,
                                                 rootKey,
                                                 cId,
                                                 maybeLocation)
      } yield m
  }

  def make[F[_]: Sync](maybeLocation: Option[Location])(
      keyManagement: KeyManagement[F],
      keyRepository: KeyRepository[F],
      macaroonService: MacaroonService[F]): Principal[F] =
    Live(maybeLocation)(keyManagement, keyRepository, macaroonService)
//  private def create[F[_]: Sync](keyManagement: KeyManagement[F],
//                                 keyRepository: KeyRepository[F],
//                                 macaroonService: MacaroonService[F],
//                                 location: Option[String])(
//      implicit F: MonadError[F, Throwable]): F[Principal[F]] =
//    for {
//      loc <- location match {
//        case Some(location) =>
//          F.fromOption(Location.from(location),
//                        new Throwable("Invalid location"))
//            .map(Some(_))
//        case None => F.pure(None)
//      }
//    } yield Live[F](keyManagement, keyRepository, macaroonService, loc)
//
//  def apply[F[_]: Sync](
//      keyManagement: KeyManagement[F],
//      keyRepository: KeyRepository[F],
//      macaroonService: MacaroonService[F])(location: String): F[Principal[F]] =
//    create(keyManagement, keyRepository, macaroonService, Some(location))

//  def apply[F[_]: Sync](): F[Principal[F]] =
//    create(None)
}
