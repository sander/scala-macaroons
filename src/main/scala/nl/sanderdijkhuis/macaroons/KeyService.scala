package nl.sanderdijkhuis.macaroons

import shapeless._

trait KeyService[F[_]] {

  def protectAsFirstParty(key: RootKey): F[Identifier]

  def protectAsThirdParty(key: RootKey, identifier: Identifier): F[Identifier]

  def recoverAsFirstParty(identifier: Identifier): F[RootKey]

  /**
    * 1P will send rootkey + mid to 3P; 3P will return new cid
    * user will request macaroon for cid; will get one with cid signed with rootkey
    */
  def recoverAsThirdParty(
      identifier: Identifier): F[RootKey :: Identifier :: HNil]
}
