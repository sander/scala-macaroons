package nl.sanderdijkhuis.macaroons4s

import cats.Monoid
import io.estatico.newtype.macros.newtype

case class Capability[C] private (maybeLocation: Option[Location],
                                  identifier: Identifier,
                                  caveats: List[Caveat],
                                  authentication: Capability.AuthenticationTag)(
    implicit cryptography: Cryptography[C],
    marshalling: Capability.Marshalling[C]) {

//  def seal(discharge: Macaroon[C]): Macaroon[C] =
//    copy(authentication = format.bind(discharge.authentication, authentication))

  private def bindForRequest(
      authentication: Capability.AuthenticationTag): Capability.Seal =
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

//  def attenuate(caveat: Caveat.FirstParty): Macaroon[C] =
//    copy(caveats = caveat :: caveats,
//         authentication = format.authenticate(authentication, caveat))
//
//  def attenuate(id: Macaroon.Id,
//                location: Macaroon.Location,
//                rootKey: Macaroon.RootKey): Macaroon[C] =
//    format
//      .authenticate(authentication, id, rootKey)
//      .pipe {
//        case (verificationKeyId, authentication) =>
//          copy(caveats = Caveat
//                 .ThirdParty(id, location, verificationKeyId) :: caveats,
//               authentication = authentication)
//      }

//  def verify(rootKey: RootKey,
//             verifier: Macaroon.Verifier,
//             dischargeMacaroons: Set[Macaroon.Bound[C]]): Boolean = {
//    def verify(identifier: Identifier,
//               caveats: List[Caveat],
//               authenticationOrSeal: Either[Macaroon.Seal, Authentication],
//               authorizingMacaroon: Macaroon[C],
//               rootKey: RootKey): Boolean = {
//      var cSig = format.authenticate(rootKey, identifier)
//      for (c <- caveats) {
//        val result = c.maybeVerificationKeyId match {
//          case Some(vId) =>
//            dischargeMacaroons.exists(
//              m =>
//                (m.identifier == c.identifier) && verify(
//                  m.identifier,
//                  m.caveats,
//                  Left(m.seal),
//                  authorizingMacaroon,
//                  format.decrypt(cSig, vId)))
//          case None => verifier(c.identifier)
//        }
//        if (!result) return false
//        cSig = format.authenticate(cSig, c.maybeVerificationKeyId, c.identifier)
//      }
//      authenticationOrSeal match {
//        case Left(seal)            => seal == authorizingMacaroon.bindForRequest(cSig)
//        case Right(authentication) => authentication == cSig
//      }
//    }
//    verify(identifier, caveats, Right(authentication), this, rootKey)
//  }

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
          .foldLeft[Option[Capability.AuthenticationTag]](Some(initialCSig)) {
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

//  def validate(rootKey: RootKey): Boolean =
//    ??? // TODO actually want this to be in smart constructor?
//  def validateSealed(target: Macaroon[C]): Boolean = ???

  def marshall(): C = marshalling.marshall(this)
}

object Capability {

  type Verifier = Identifier => Boolean
  // model verifiers as functions, compose with short circuit true. monoids?
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

  @newtype case class AuthenticationTag(toByteArray: Array[Byte])

  @newtype case class Seal(toByteArray: Array[Byte])

  @newtype case class Key(toByteArray: Array[Byte])

//  @newtype case class RootKey(override val toByteArray: Array[Byte])
//      extends Key(toByteArray)

//  @newtype case class AnyKey(toByteArray: Array[Byte])

//  @newtype case class DataToBeAuthenticated(toByteArray: Array[Byte])

  trait Marshalling[C] {
    def marshall(macaroon: Capability[C]): C
    def marshall(bound: Bound[C]): C
    def unmarshallMacaroon(value: C): Option[Capability[C]]
    def unmarshallBound(value: C): Option[Bound[C]]
  }

//  private val algorithm = "HmacSHA256"
//
//  private def authenticate(dataToBeAuthenticated: DataToBeAuthenticated,
//                           key: Key): Authentication =
//    Mac
//      .getInstance(algorithm)
//      .tap(_.init(new SecretKeySpec(key.toByteArray, algorithm)))
//      .doFinal(dataToBeAuthenticated.toByteArray)
//      .pipe(Authentication)

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
