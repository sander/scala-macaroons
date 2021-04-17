package nl.sanderdijkhuis.macaroons.integration.example.services

import cats.Monad
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon.{
  Authority, Endpoint, Macaroon
}
import nl.sanderdijkhuis.macaroons.integration.example.domain.authentication.PrincipalId
import nl.sanderdijkhuis.macaroons.integration.example.domain.photo.{
  Photo, PhotoId
}
import nl.sanderdijkhuis.macaroons.services.{MacaroonService, PrincipalService}

object PhotoService {

  case class PhotoUploaded(photoId: PhotoId)

  // TODO s/PhotoId/Macaroon?

  case class Authorization(macaroon: Macaroon with Authority)
  case class Authorized()

  sealed trait PrivilegedOperation
  case object Create extends PrivilegedOperation

  sealed trait ProtectedResource
  case object PhotoClass extends ProtectedResource

  def upload[F[_]: Monad](
      principal: PrincipalService[F, Endpoint[F, MacaroonService.RootKey]],
      store: (PhotoId, Photo) => F[Unit],
      authorize: (
          PrincipalId,
          PrivilegedOperation,
          ProtectedResource) => F[Authorized])(photo: Photo)(
      userId: PrincipalId,
      discharges: Set[Macaroon]): F[PhotoUploaded] =
    for {
      _ <- authorize(userId, Create, PhotoClass)
      m <- principal.assert()
      _ <- store(PhotoId(m), photo)
    } yield PhotoUploaded(PhotoId(m))
  // don't mix entity IDs and macaroons

  def view[F[_]](photoId: PhotoId)(
      macaroon: Macaroon,
      discharges: Set[Macaroon]): F[Photo] = ???
}
