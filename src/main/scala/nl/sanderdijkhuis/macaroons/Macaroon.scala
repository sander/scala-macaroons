package nl.sanderdijkhuis.macaroons

import cats.Applicative
import cats.implicits._

case class Macaroon(maybeLocation: Option[Location],
                    identifier: Identifier,
                    caveats: Vector[Caveat],
                    authentication: Authentication)

object Macaroon {

  def create[F[_]](key: RootKey,
                   identifier: Identifier,
                   maybeLocation: Option[Location])(
      implicit cryptography: Cryptography[F]): Macaroon with Authority =
    Macaroon(maybeLocation,
             identifier,
             Vector.empty,
             cryptography.authenticate(key, identifier))
      .asInstanceOf[Macaroon with Authority]

  implicit class AuthorityOps[F[_]: Applicative](
      macaroon: Macaroon with Authority) {

    private def bindForRequest(authentication: Authentication)(
        implicit cryptography: Cryptography[F]): Authentication =
      cryptography.bind(authentication, macaroon.authentication)

    private def addCaveatHelper(identifier: Identifier,
                                maybeVerificationKeyId: Option[Challenge],
                                maybeLocation: Option[Location])(
        implicit cryptography: Cryptography[F]): Macaroon with Authority =
      macaroon
        .copy(
          caveats = macaroon.caveats :+ Caveat(maybeLocation,
                                               identifier,
                                               maybeVerificationKeyId),
          authentication = cryptography.authenticate(macaroon.authentication,
                                                     maybeVerificationKeyId,
                                                     identifier)
        )
        .asInstanceOf[Macaroon with Authority]

    def bind(capabilities: Set[Macaroon])(
        implicit cryptography: Cryptography[F]): Set[Macaroon] =
      capabilities.map(
        d =>
          Macaroon(d.maybeLocation,
                   d.identifier,
                   d.caveats,
                   bindForRequest(d.authentication)))

    def addFirstPartyCaveat(identifier: Identifier)(
        implicit cryptography: Cryptography[F]): Macaroon with Authority =
      addCaveatHelper(identifier, None, None)

    def addThirdPartyCaveat(key: RootKey,
                            identifier: Identifier,
                            maybeLocation: Option[Location])(
        implicit cryptography: Cryptography[F]): F[Macaroon with Authority] =
      cryptography
        .encrypt(macaroon.authentication, key)
        .map(c => addCaveatHelper(identifier, Some(c), maybeLocation))

    def verify(key: RootKey, verifier: Verifier, Ms: Set[Macaroon])(
        implicit cryptography: Cryptography[F]): VerificationResult = {
      def helper(discharge: Option[Macaroon],
                 k: RootKey): VerificationResult = {
        val M = discharge.getOrElse(macaroon)
        val cSig = cryptography.authenticate(k, M.identifier)
        val maybeAuthentication =
          M.caveats
            .foldLeft[Option[Authentication]](Some(cSig)) {
              case (Some(cSig), Caveat(_, cId, vId)) => {
                val caveatsVerified = vId match {
                  case None => verifier(cId)
                  case Some(vId)
                      if Ms.exists(
                        m =>
                          (m.identifier == cId) && cryptography
                            .decrypt(cSig, vId)
                            .map(helper(Some(m), _).isVerified)
                            .isDefined) =>
                    Verified
                  case _ => VerificationFailed
                }
                Option.when(caveatsVerified.isVerified)(
                  cryptography.authenticate(cSig, vId, cId))
              }
              case (None, _) => None
            }
        (maybeAuthentication, discharge) match {
          case (Some(cSig), Some(M))
              if M.authentication == bindForRequest(cSig) =>
            Verified
          case (Some(cSig), None) if macaroon.authentication == cSig => Verified
          case _                                                     => VerificationFailed
        }
      }
      helper(None, key)
    }
  }
}
