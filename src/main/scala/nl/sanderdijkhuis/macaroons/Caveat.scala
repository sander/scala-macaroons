package nl.sanderdijkhuis.macaroons

import io.estatico.newtype.macros.newtype

//sealed trait Caveat
case class Caveat(maybeLocation: Option[Location],
                  identifier: Identifier,
                  maybeVerificationKeyId: Option[VerificationKeyId])
object Caveat {

//  @newtype case class FirstParty(override val toString: String) extends Caveat
//
//  case class ThirdParty(id: Macaroon.Id,
//                        location: Macaroon.Location,
//                        verificationKeyId: VerificationKeyId)
//      extends Caveat
}
