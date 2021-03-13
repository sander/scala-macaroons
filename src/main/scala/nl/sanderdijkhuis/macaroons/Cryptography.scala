package nl.sanderdijkhuis.macaroons

trait Cryptography {

  def authenticate(key: Key, identifier: Identifier): Authentication

  def authenticate(authentication: Authentication,
                   maybeChallenge: Option[Challenge],
                   identifier: Identifier): Authentication

  def encrypt(authentication: Authentication, rootKey: Key): Challenge

  def decrypt(authentication: Authentication, challenge: Challenge): Key

  def bind(discharging: Authentication,
           authorizing: Authentication): Authentication
}
