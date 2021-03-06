package nl.sanderdijkhuis.macaroons

case class Caveat(maybeLocation: Option[Location],
                  identifier: Identifier,
                  maybeVerificationKeyId: Option[VerificationKeyId])
