package nl.sanderdijkhuis.macaroons

import com.google.crypto.tink.subtle.XChaCha20Poly1305
import scodec.bits.ByteVector

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

object MacaroonCryptography extends Cryptography[SerializedMacaroon] {

  private val algorithm = "HmacSHA256"

  private def hmac(key: ByteVector, message: ByteVector): ByteVector =
    Mac
      .getInstance(algorithm)
      .tap(_.init(new SecretKeySpec(key.toArray, algorithm)))
      .doFinal(message.toArray)
      .pipe(ByteVector(_))

  override def authenticate(key: Key, identifier: Identifier): Authentication =
    Authentication(hmac(key.toByteVector, identifier.toByteVector))

  override def authenticate(authentication: Authentication,
                            maybeChallenge: Option[Challenge],
                            identifier: Identifier): Authentication =
    Authentication(
      hmac(authentication.toByteVector,
           maybeChallenge
             .map(_.toByteVector)
             .getOrElse(ByteVector.empty) ++ identifier.toByteVector))

  override def encrypt(authentication: Authentication,
                       rootKey: Key /* TODO differently? */ ): Challenge =
    new XChaCha20Poly1305(authentication.toByteVector.toArray)
      .encrypt(rootKey.toByteVector.toArray, Array.empty)
      .pipe(b => Challenge(ByteVector(b)))

  override def decrypt(authentication: Authentication,
                       challenge: Challenge): Key =
    new XChaCha20Poly1305(authentication.toByteVector.toArray)
      .decrypt(challenge.toByteVector.toArray, Array.empty)
      .pipe(b => Key(ByteVector(b)))

  private def hash(value: ByteVector): ByteVector =
    MessageDigest
      .getInstance("SHA-256")
      .digest(value.toArray)
      .pipe(ByteVector(_))

  override def bind(discharging: Authentication,
                    authorizing: Authentication): Seal =
    hash(discharging.toByteVector ++ authorizing.toByteVector).pipe(Seal.apply)
}
