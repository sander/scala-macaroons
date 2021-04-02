package nl.sanderdijkhuis.macaroons.services

import cats.effect._
import cats.implicits._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.domain.verification.{
  VerificationFailed,
  VerificationResult,
  Verifier
}
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

trait PrincipalService[F[_], ThirdParty] {

  def assert(): F[Macaroon with Authority]

  def getPredicate(identifier: Identifier): F[Option[Predicate]]

  def discharge(identifier: Identifier): F[Macaroon with Authority]

  def addFirstPartyCaveat(macaroon: Macaroon with Authority,
                          identifier: Identifier): F[Macaroon with Authority]

  def addThirdPartyCaveat(macaroon: Macaroon with Authority,
                          predicate: Predicate,
                          thirdParty: ThirdParty): F[Macaroon with Authority]

  def verify(macaroon: Macaroon with Authority,
             verifier: Verifier,
             dischargeMacaroons: Set[Macaroon]): F[VerificationResult]
}

object PrincipalService {

  case class Live[F[_]: Sync, HmacAlgorithm](maybeLocation: Option[Location])(
      keyRepository: KeyProtectionService[F, MacSigningKey[HmacAlgorithm]],
      macaroonService: MacaroonService[F, MacSigningKey[HmacAlgorithm]])(
      implicit keyGen: SymmetricKeyGen[F, HmacAlgorithm, MacSigningKey])
      extends PrincipalService[F, Endpoint[F, MacSigningKey[HmacAlgorithm]]] {

    override def assert(): F[Macaroon with Authority] =
      for {
        rootKey <- keyGen.generateKey
        cId <- keyRepository.protectRootKey(rootKey)
        m <- macaroonService.generate(cId, rootKey, maybeLocation)
      } yield m

    override def discharge(identifier: Identifier): F[Macaroon with Authority] =
      for {
        rootKey <- keyRepository
          .restoreRootKeyAndPredicate(identifier)
          .flatMap[MacSigningKey[HmacAlgorithm]] {
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
        thirdParty: Endpoint[F, MacSigningKey[HmacAlgorithm]])
      : F[Macaroon with Authority] =
      for {
        rootKey <- keyGen.generateKey
        cId <- thirdParty.prepare(rootKey, predicate)
        m <- macaroonService.addThirdPartyCaveat(macaroon,
                                                 rootKey,
                                                 cId,
                                                 thirdParty.maybeLocation)
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
      keyRepository: KeyProtectionService[F, MacSigningKey[HMACSHA256]])(
      implicit keyGen: SymmetricKeyGen[F, HMACSHA256, MacSigningKey])
    : PrincipalService[F, Endpoint[F, MacSigningKey[HMACSHA256]]] =
    Live(maybeLocation)(keyRepository, MacaroonService[F])

  def makeInMemory[F[_]: Sync](maybeLocation: Option[Location])(
      implicit keyGen: SymmetricKeyGen[F, HMACSHA256, MacSigningKey])
    : F[PrincipalService[F, Endpoint[F, MacSigningKey[HMACSHA256]]]] =
    KeyProtectionService
      .inMemory[F, MacSigningKey[HMACSHA256]]
      .map(make(maybeLocation))
}
