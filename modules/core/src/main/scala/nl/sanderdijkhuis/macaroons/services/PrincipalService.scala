package nl.sanderdijkhuis.macaroons.services

import cats.effect._
import cats.implicits._
import eu.timepit.refined.predicates.all.NonEmpty
import eu.timepit.refined.refineV
import nl.sanderdijkhuis.macaroons.domain.verification.{
  VerificationFailed,
  VerificationResult,
  Verifier
}
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.types.bytes._
import scodec.bits.ByteVector
import tsec.common.SecureRandomId

trait PrincipalService[F[_]] {

  def assert(): F[Macaroon with Authority]

  def getPredicate(identifier: Identifier): F[Option[Predicate]]

  def discharge(identifier: Identifier): F[Macaroon with Authority]

  def addFirstPartyCaveat(macaroon: Macaroon with Authority,
                          identifier: Identifier): F[Macaroon with Authority]

  def addThirdPartyCaveat(
      macaroon: Macaroon with Authority,
      predicate: Predicate,
      thirdParty: EndpointService[F]): F[Macaroon with Authority]

  def verify(macaroon: Macaroon with Authority,
             verifier: Verifier,
             dischargeMacaroons: Set[Macaroon]): F[VerificationResult]
}

object PrincipalService {

  def generateRootKey[F[_]: Sync](): F[RootKey] =
    for {
      raw <- SecureRandomId.Strong.generateF
      key <- Sync[F].fromEither(
        refineV[NonEmpty](ByteVector(raw.getBytes)).leftMap(new Throwable(_)))
    } yield RootKey(key)

  case class Live[F[_]: Sync](maybeLocation: Option[Location])(
      keyRepository: KeyProtectionService[F],
      macaroonService: MacaroonService[F])
      extends PrincipalService[F] {

    override def assert(): F[Macaroon with Authority] =
      for {
        rootKey <- generateRootKey()
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
        thirdParty: EndpointService[F]): F[Macaroon with Authority] =
      for {
        rootKey <- generateRootKey()
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
      keyRepository: KeyProtectionService[F]): PrincipalService[F] =
    Live(maybeLocation)(keyRepository, MacaroonService[F])

  def makeInMemory[F[_]: Sync](
      maybeLocation: Option[Location]): F[PrincipalService[F]] =
    KeyProtectionService.inMemory.map(PrincipalService.make(maybeLocation))

  def makeInMemory[F[_]: Sync](location: Location): F[PrincipalService[F]] =
    makeInMemory(Some(location))
  def makeInMemory[F[_]: Sync](): F[PrincipalService[F]] =
    makeInMemory(None)
}
