package nl.sanderdijkhuis.macaroons

import shapeless._

trait KeyService[F[_]] {

  def generate(): F[RootKey]

  def protectAsFirstParty(key: RootKey): F[Identifier]

  def recoverAsFirstParty(identifier: Identifier): F[RootKey]

  def protectAsThirdParty(key: RootKey, identifier: Identifier): F[Identifier]

  /**
    * 1P will send rootkey + mid to 3P; 3P will return new cid
    * user will request macaroon for cid; will get one with cid signed with rootkey
    */
  def recoverAsThirdParty(
      identifier: Identifier): F[RootKey :: Identifier :: HNil]
}

object KeyService {

  def apply[F[_]](implicit service: KeyService[F]): KeyService[F] = service
}
