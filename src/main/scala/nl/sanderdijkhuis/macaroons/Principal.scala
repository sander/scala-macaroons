package nl.sanderdijkhuis.macaroons

import cats._
import cats.data.OptionT
import cats.effect._
import cats.implicits._
import scodec.bits.ByteVector

trait Principal[F[_]] {

//  def maybeLocation: Option[Location]

  def assert(): F[Macaroon with Authority]

  def getPredicate(identifier: Identifier): F[Option[Predicate]]

  def discharge(identifier: Identifier): F[Macaroon with Authority]

  def addFirstPartyCaveat(macaroon: Macaroon with Authority,
                          identifier: Identifier): F[Macaroon with Authority]

  def addThirdPartyCaveat(macaroon: Macaroon with Authority,
                          predicate: Predicate,
                          thirdParty: ThirdParty[F]): F[Macaroon with Authority]

  def verify(macaroon: Macaroon with Authority,
             verifier: Verifier,
             dischargeMacaroons: Set[Macaroon]): F[VerificationResult]
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

    override def discharge(identifier: Identifier): F[Macaroon with Authority] =
      for {
        rootKey <- keyRepository
          .restoreRootKeyAndPredicate(identifier)
          .flatMap[RootKey] {
            case Some((rootKey, _)) => rootKey.pure[F]
            case None               => Sync[F].raiseError(new Throwable("Not found"))
          }
        m <- macaroonService.generate(identifier, rootKey, maybeLocation)
      } yield m

    override def addFirstPartyCaveat(
        macaroon: Macaroon with Authority,
        identifier: Identifier): F[Macaroon with Authority] =
      macaroonService.addFirstPartyCaveat(macaroon, identifier)

    override def addThirdPartyCaveat(
        macaroon: Macaroon with Authority,
        predicate: Predicate,
        thirdParty: ThirdParty[F]): F[Macaroon with Authority] =
      for {
        rootKey <- keyManagement.generateRootKey()
        cId <- thirdParty.prepare(rootKey, predicate)
        loc <- thirdParty.maybeLocation
        m <- macaroonService.addThirdPartyCaveat(macaroon, rootKey, cId, loc)
      } yield m

    override def verify(
        macaroon: Macaroon with Authority,
        verifier: Verifier,
        dischargeMacaroons: Set[Macaroon]): F[VerificationResult] =
      for {
        rootKey <- keyRepository.restoreRootKey(macaroon.id)
        result <- rootKey match {
          case Some(rootKey) =>
            macaroonService.verify(macaroon,
                                   rootKey,
                                   verifier,
                                   dischargeMacaroons)
          case None => VerificationFailed.pure[F]
        }
      } yield result

    override def getPredicate(identifier: Identifier): F[Option[Predicate]] =
      keyRepository.restoreRootKeyAndPredicate(identifier).map {
        case Some((_, predicate)) => Some(predicate)
        case None                 => None
      }
  }

  def make[F[_]: Sync](maybeLocation: Option[Location])(
      keyRepository: KeyRepository[F]): Principal[F] =
    Live(maybeLocation)(KeyManagement[F], keyRepository, MacaroonService[F])

  def makeInMemory[F[_]: Sync](
      maybeLocation: Option[Location]): F[Principal[F]] =
    KeyRepository.inMemory.map(Principal.make(maybeLocation))

  def makeInMemory[F[_]: Sync](location: Location): F[Principal[F]] =
    makeInMemory(Some(location))
  def makeInMemory[F[_]: Sync](): F[Principal[F]] =
    makeInMemory(None)
}
