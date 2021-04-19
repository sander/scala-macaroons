package nl.sanderdijkhuis.macaroons.services

import nl.sanderdijkhuis.macaroons.cryptography._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.repositories._

import cats._
import cats.implicits._
import tsec.cipher.symmetric._
import tsec.cipher.symmetric.bouncy._
import tsec.mac.jca._

trait DischargeService[F[_]] {

  def getPredicate(identifier: Identifier): F[Option[Predicate]]

  def discharge(identifier: Identifier): F[Option[Macaroon with Authority]]
}

object DischargeService {

  case class Live[F[_], HmacAlgorithm, AuthCipher, E >: CryptographyError](
      maybeLocation: Option[Location])(
      dischargeKeyRepository: KeyRepository[
        F,
        Identifier,
        (MacSigningKey[HmacAlgorithm], Predicate)],
      macaroonService: MacaroonService[F, MacSigningKey[HmacAlgorithm], Iv[
        AuthCipher]])(implicit M: MonadError[F, E])
      extends DischargeService[F] {

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

    override def getPredicate(identifier: Identifier): F[Option[Predicate]] =
      dischargeKeyRepository.recover(identifier).map {
        case Some((_, predicate)) => Some(predicate)
        case None                 => None
      }
  }

  def make[F[_], E >: CryptographyError](maybeLocation: Option[Location])(
      macaroonService: MacaroonService[F, MacSigningKey[HMACSHA256], Iv[
        XChaCha20Poly1305]],
      dischargeKeyRepository: KeyRepository[
        F,
        Identifier,
        (MacSigningKey[HMACSHA256], Predicate)])(implicit
      F: MonadError[F, E]): DischargeService[F] =
    Live[F, HMACSHA256, XChaCha20Poly1305, E](maybeLocation)(
      dischargeKeyRepository,
      macaroonService)
}
