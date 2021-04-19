package nl.sanderdijkhuis.macaroons.services

import nl.sanderdijkhuis.macaroons.domain._

import cats._
import cats.data._
import cats.implicits._
import tsec.cipher.symmetric._
import tsec.mac.jca._

trait CaveatService[F[_], Context] {

  def attenuate(predicate: Predicate): F[Unit]

  def confine(context: Context, predicate: Predicate): F[Identifier]
}

object CaveatService {

  type StatefulCaveatService[F[_], HmacAlgorithm] =
    CaveatService[Transformation[F, *], Context[F, MacSigningKey[
      HmacAlgorithm]]]

  def make[F[_]: Monad, HmacAlgorithm, AuthCipher](
      macaroonService: MacaroonService[F, MacSigningKey[HmacAlgorithm], Iv[
        AuthCipher]],
      generateKey: F[MacSigningKey[HmacAlgorithm]],
      generateIv: F[Iv[AuthCipher]]): StatefulCaveatService[F, HmacAlgorithm] =
    new CaveatService[Transformation[F, *], Context[F, MacSigningKey[
      HmacAlgorithm]]] {

      override def attenuate(predicate: Predicate): Transformation[F, Unit] =
        StateT(macaroonService.addFirstPartyCaveat(_, predicate.identifier).map(
          (_, ())))

      override def confine(
          context: Context[F, MacSigningKey[HmacAlgorithm]],
          predicate: Predicate): Transformation[F, Identifier] =
        StateT(m =>
          for {
            rootKey <- generateKey
            cId     <- context.prepare(rootKey, predicate)
            iv      <- generateIv
            m <- macaroonService
              .addThirdPartyCaveat(m, rootKey, iv, cId, context.maybeLocation)
          } yield (m, cId))
    }
}
