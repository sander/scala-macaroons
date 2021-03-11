package nl.sanderdijkhuis.macaroons

import cats.Monoid

case class Capability[C] private (maybeLocation: Option[Location],
                                  identifier: Identifier,
                                  caveats: List[Caveat],
                                  authentication: AuthenticationTag)(
    implicit cryptography: Cryptography[C],
    marshalling: Capability.Marshalling[C]) {

  private def bindForRequest(authentication: AuthenticationTag): Seal =
    cryptography.bind(authentication, this.authentication)

  private def addCaveatHelper(identifier: Identifier,
                              maybeVerificationKeyId: Option[VerificationKeyId],
                              maybeLocation: Option[Location]): Capability[C] =
    copy(
      caveats = Caveat(maybeLocation, identifier, maybeVerificationKeyId) :: caveats,
      authentication = cryptography.authenticate(authentication,
                                                 maybeVerificationKeyId,
                                                 identifier)
    )

  def bind(macaroons: Set[Capability[C]]): Set[Capability.Bound[C]] =
    macaroons.map(d =>
      Capability.Bound.from(this, bindForRequest(d.authentication)))

  def attenuate(identifier: Identifier): Capability[C] =
    addCaveatHelper(identifier, None, None)

  def attenuate(rootKey: RootKey,
                identifier: Identifier,
                maybeLocation: Option[Location]): Capability[C] =
    addCaveatHelper(identifier,
                    Some(cryptography.encrypt(authentication, rootKey)),
                    maybeLocation)

  def verify(rootKey: RootKey,
             verifier: Capability.Verifier,
             dischargeMacaroons: Set[Capability.Bound[C]]): Boolean = {
    def helper(maybeDischargeMacaroon: Option[Capability.Bound[C]],
               rootKey: RootKey): Boolean = {
      val initialCSig = cryptography.authenticate(
        rootKey,
        maybeDischargeMacaroon.map(_.identifier).getOrElse(identifier))
      val caveats = maybeDischargeMacaroon
        .map(_.caveats)
        .getOrElse(this.caveats)
      // use takeWhile to abort early?
      val maybeAuthentication =
        caveats
          .foldLeft[Option[AuthenticationTag]](Some(initialCSig)) {
            case (Some(cSig), caveat) => {
              val caveatsVerified = caveat.maybeVerificationKeyId
                .map(
                  vId =>
                    dischargeMacaroons.exists(
                      m =>
                        (m.identifier == caveat.identifier) && helper(
                          Some(m),
                          cryptography.decrypt(cSig, vId))))
                .getOrElse(verifier(caveat.identifier))
              Option.when(caveatsVerified)(
                cryptography.authenticate(cSig,
                                          caveat.maybeVerificationKeyId,
                                          caveat.identifier))
            }
            case (None, _) => None
          }
      (maybeAuthentication, maybeDischargeMacaroon) match {
        case (None, _)                 => false
        case (Some(cSig), Some(bound)) => bound.seal == bindForRequest(cSig)
        case (Some(cSig), None)        => authentication == cSig
      }
    }
    helper(None, rootKey)
  }

  def marshall(): C = marshalling.marshall(this)
}

object Capability {

  type Verifier = Identifier => Boolean

  implicit object VerifierMonoid extends Monoid[Verifier] {
    override def empty: Verifier = _ => false
    override def combine(x: Verifier, y: Verifier): Verifier = c => x(c) || y(c)
  }

  case class Bound[C](maybeLocation: Option[Location],
                      identifier: Identifier,
                      caveats: List[Caveat],
                      seal: Seal)
  object Bound {

    def from[C](macaroon: Capability[C], seal: Seal): Bound[C] =
      Bound(macaroon.maybeLocation, macaroon.identifier, macaroon.caveats, seal)
  }

  trait Marshalling[C] {
    def marshall(macaroon: Capability[C]): C
    def marshall(bound: Bound[C]): C
    def unmarshallMacaroon(value: C): Option[Capability[C]]
    def unmarshallBound(value: C): Option[Bound[C]]
  }

  def create[C](rootKey: RootKey,
                identifier: Identifier,
                maybeLocation: Option[Location])(
      implicit cryptography: Cryptography[C],
      marshalling: Marshalling[C]): Capability[C] =
    Capability(maybeLocation,
               identifier,
               List.empty,
               cryptography.authenticate(rootKey, identifier))
}
