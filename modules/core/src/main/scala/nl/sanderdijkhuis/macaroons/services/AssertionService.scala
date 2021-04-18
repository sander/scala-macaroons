package nl.sanderdijkhuis.macaroons.services

import cats._
import cats.effect._
import cats.implicits._
import nl.sanderdijkhuis.macaroons.cryptography.util.CryptographyError
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.domain.verification._
import nl.sanderdijkhuis.macaroons.repositories.KeyRepository
import tsec.cipher.symmetric.Iv
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.{HMACSHA256, MacSigningKey}

trait AssertionService[F[_]] {

  def assert(): F[Macaroon with Authority]

  def verify(
      macaroon: Macaroon with Authority,
      verifier: Verifier,
      dischargeMacaroons: Set[Macaroon]): F[VerificationResult]
}

object AssertionService {

  case class Live[F[+_], HmacAlgorithm, AuthCipher, E >: CryptographyError](
      maybeLocation: Option[Location])(
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HmacAlgorithm]],
      macaroonService: MacaroonService[F, MacSigningKey[HmacAlgorithm], Iv[
        AuthCipher]],
      generateKey: F[MacSigningKey[HmacAlgorithm]])(implicit
      M: MonadError[F, E])
      extends AssertionService[F] {

    override def assert(): F[Macaroon with Authority] =
      for {
        rootKey <- generateKey
        cId     <- rootKeyRepository.protect(rootKey)
        m       <- macaroonService.generate(cId, rootKey, maybeLocation)
      } yield m

    override def verify(
        macaroon: Macaroon with Authority,
        verifier: Verifier,
        dischargeMacaroons: Set[Macaroon]): F[VerificationResult] =
      rootKeyRepository.recover(macaroon.id).flatMap {
        case Some(rootKey) => macaroonService
            .verify(macaroon, rootKey, verifier, dischargeMacaroons)
        case None => VerificationFailed.pure[F]
      }
  }

  def make[F[+_], E >: CryptographyError, HmacAlgorithm, AuthCipher](
      maybeLocation: Option[Location])(
      macaroonService: MacaroonService[F, MacSigningKey[HmacAlgorithm], Iv[
        AuthCipher]],
      rootKeyRepository: KeyRepository[F, Identifier, MacSigningKey[
        HmacAlgorithm]],
      generateKey: F[MacSigningKey[HmacAlgorithm]])(implicit
      F: MonadError[F, E]): AssertionService[F] =
    Live[F, HmacAlgorithm, AuthCipher, E](maybeLocation)(
      rootKeyRepository,
      macaroonService,
      generateKey)
}
