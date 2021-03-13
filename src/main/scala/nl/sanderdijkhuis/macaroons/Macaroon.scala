package nl.sanderdijkhuis.macaroons

case class Macaroon[T <: MacaroonState](maybeLocation: Option[Location],
                                        identifier: Identifier,
                                        caveats: Vector[Caveat],
                                        authentication: Authentication)

object Macaroon {

  def create(key: Key, identifier: Identifier, maybeLocation: Option[Location])(
      implicit cryptography: Cryptography): Macaroon[Unbound] =
    Macaroon[Unbound](maybeLocation,
                      identifier,
                      Vector.empty,
                      cryptography.authenticate(key, identifier))

  implicit class UnboundMacaroonOps(macaroon: Macaroon[Unbound])(
      implicit val cryptography: Cryptography) {

    private def bindForRequest(macaroon: Macaroon[Unbound]): Authentication =
      cryptography.bind(this.macaroon.authentication, macaroon.authentication)

    private def addCaveatHelper(
        macaroon: Macaroon[Unbound],
        identifier: Identifier,
        maybeVerificationKeyId: Option[Challenge],
        maybeLocation: Option[Location]): Macaroon[Unbound] =
      macaroon.copy(
        caveats = macaroon.caveats :+ Caveat(maybeLocation,
                                             identifier,
                                             maybeVerificationKeyId),
        authentication = cryptography.authenticate(macaroon.authentication,
                                                   maybeVerificationKeyId,
                                                   identifier)
      )

    def bind(capabilities: Set[Macaroon[Unbound]]): Set[Macaroon[Discharge]] =
      capabilities.map(
        d =>
          Macaroon[Discharge](d.maybeLocation,
                              d.identifier,
                              d.caveats,
                              bindForRequest(d)))

    def attenuate(identifier: Identifier): Macaroon[Unbound] =
      addCaveatHelper(macaroon, identifier, None, None)

    def attenuate(key: Key,
                  identifier: Identifier,
                  maybeLocation: Option[Location]): Macaroon[Unbound] =
      addCaveatHelper(macaroon,
                      identifier,
                      Some(cryptography.encrypt(macaroon.authentication, key)),
                      maybeLocation)

    def verify(key: Key,
               verifier: Verifier,
               passes: Set[Macaroon[Discharge]]): VerificationResult = {
      def helper(maybeDischargeMacaroon: Option[Macaroon[Discharge]],
                 k: Key): VerificationResult = {
        val cSig = cryptography.authenticate(k, maybeDischargeMacaroon match {
          case Some(m) => m.identifier
          case None    => macaroon.identifier
        })
        val caveats = maybeDischargeMacaroon
          .map(_.caveats)
          .getOrElse(macaroon.caveats)
        // use takeWhile to abort early?
        val maybeAuthentication =
          caveats
            .foldLeft[Option[Authentication]](Some(cSig)) {
              case (Some(cSig), caveat) => {
                val caveatsVerified = caveat.maybeChallenge match {
                  case None => verifier(caveat.identifier)
                  case Some(vId)
                      if passes.exists(
                        m =>
                          (m.identifier == caveat.identifier) && helper(
                            Some(m),
                            cryptography.decrypt(cSig, vId)).isVerified) =>
                    Verified
                  case _ => VerificationFailed
                }
                Option.when(caveatsVerified.isVerified)(
                  cryptography.authenticate(cSig,
                                            caveat.maybeChallenge,
                                            caveat.identifier))
              }
              case (None, _) => None
            }
        (maybeAuthentication, maybeDischargeMacaroon) match {
          case (None, _) => VerificationFailed
          case (Some(cSig), Some(bound))
              if bound.authentication == bindForRequest(macaroon, cSig) =>
            Verified
          case (Some(cSig), Some(bound))
              if bound.authentication != bindForRequest(macaroon, cSig) =>
            VerificationFailed
          case (Some(cSig), None) if macaroon.authentication == cSig => Verified
          case (Some(cSig), None) if macaroon.authentication != cSig =>
            VerificationFailed
        }
      }
      helper(None, key)
    }
  }
}
