package nl.sanderdijkhuis.macaroons

trait Cryptography[C] {

  def authenticate(key: RootKey, identifier: Identifier): AuthenticationTag

  def authenticate(authentication: AuthenticationTag,
                   maybeVerificationKeyId: Option[VerificationKeyId],
                   identifier: Identifier): AuthenticationTag

  def encrypt(authentication: AuthenticationTag,
              rootKey: RootKey): VerificationKeyId

  def decrypt(authentication: AuthenticationTag,
              verificationKeyId: VerificationKeyId): RootKey

  def bind(discharging: AuthenticationTag, authorizing: AuthenticationTag): Seal
}
