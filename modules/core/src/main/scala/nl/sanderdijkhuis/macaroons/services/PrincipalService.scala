package nl.sanderdijkhuis.macaroons.services

import cats._
import cats.effect.Sync
import cats.implicits._
import nl.sanderdijkhuis.macaroons.cryptography.util.CryptographyError
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.domain.verification.{
  VerificationFailed, VerificationResult, Verifier
}
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import tsec.cipher.symmetric.Iv
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

trait PrincipalService[F[_]] {

  def assert(): F[Macaroon with Authority]

  def getPredicate(identifier: Identifier): F[Option[Predicate]]

  def discharge(identifier: Identifier): F[Option[Macaroon with Authority]]

  def verify(
      macaroon: Macaroon with Authority,
      verifier: Verifier,
      dischargeMacaroons: Set[Macaroon]): F[VerificationResult]
}

object PrincipalService {

  case class Live[F[_], HmacAlgorithm, AuthCipher, E >: CryptographyError](
      maybeLocation: Option[Location])(
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HmacAlgorithm]],
      dischargeKeyRepository: KeyRepository[
        F,
        Identifier,
        (MacSigningKey[HmacAlgorithm], Predicate)],
      macaroonService: MacaroonService[F, MacSigningKey[HmacAlgorithm], Iv[
        AuthCipher]],
      generateKey: F[MacSigningKey[HmacAlgorithm]],
      generateIv: F[Iv[AuthCipher]])(implicit M: MonadError[F, E])
      extends PrincipalService[F] {

    override def assert(): F[Macaroon with Authority] =
      for {
        rootKey <- generateKey
        cId     <- rootKeyRepository.protect(rootKey)
        m       <- macaroonService.generate(cId, rootKey, maybeLocation)
      } yield m

    override def discharge(
        identifier: Identifier): F[Option[Macaroon with Authority]] =
      for {
        rootKey <- dischargeKeyRepository.recover(identifier)
          .flatMap[Option[MacSigningKey[HmacAlgorithm]]] {
            case Some((rootKey, _)) => rootKey.some.pure[F]
            case None               => Monad[F].pure(None)
          }
        m <- rootKey match {
          case Some(rootKey) => macaroonService
              .generate(identifier, rootKey, maybeLocation).map(_.some)
          case None => None.pure[F]
        }
      } yield m

    override def verify(
        macaroon: Macaroon with Authority,
        verifier: Verifier,
        dischargeMacaroons: Set[Macaroon]): F[VerificationResult] =
      for {
        rootKey <- rootKeyRepository.recover(macaroon.id)
        result <- rootKey match {
          case Some(rootKey) => macaroonService
              .verify(macaroon, rootKey, verifier, dischargeMacaroons)
          case None => VerificationFailed.pure[F]
        }
      } yield result

    override def getPredicate(identifier: Identifier): F[Option[Predicate]] =
      dischargeKeyRepository.recover(identifier).map {
        case Some((_, predicate)) => Some(predicate)
        case None                 => None
      }
  }

  def make[F[_], E >: CryptographyError](maybeLocation: Option[Location])(
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HMACSHA256]],
      dischargeKeyRepository: KeyRepository[
        F,
        Identifier,
        (MacSigningKey[HMACSHA256], Predicate)],
      generateKey: F[MacSigningKey[HMACSHA256]],
      generateIv: F[Iv[XChaCha20Poly1305]])(implicit
      F: MonadError[F, E]): PrincipalService[F] =
    Live[F, HMACSHA256, XChaCha20Poly1305, E](maybeLocation)(
      rootKeyRepository,
      dischargeKeyRepository,
      MacaroonService[F, E],
      generateKey,
      generateIv)

  def make[F[_]: Sync](maybeLocation: Option[Location])(
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HMACSHA256]],
      dischargeKeyRepository: KeyRepository[
        F,
        Identifier,
        (MacSigningKey[HMACSHA256], Predicate)]): PrincipalService[F] =
    Live[F, HMACSHA256, XChaCha20Poly1305, Throwable](maybeLocation)(
      rootKeyRepository,
      dischargeKeyRepository,
      MacaroonService[F, Throwable],
      HMACSHA256.generateKey[F],
      XChaCha20Poly1305.defaultIvGen[F].genIv)
}
