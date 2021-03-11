package nl.sanderdijkhuis.macaroons

import com.google.crypto.tink.subtle.XChaCha20Poly1305
import scodec.bits.ByteVector

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

object MacaroonCryptography extends Cryptography[MacaroonV2] {

  private val algorithm = "HmacSHA256"

  private def hmac(key: ByteVector, message: ByteVector): ByteVector =
    Mac
      .getInstance(algorithm)
      .tap(_.init(new SecretKeySpec(key.toArray, algorithm)))
      .doFinal(message.toArray)
      .pipe(ByteVector(_))

  override def authenticate(key: RootKey,
                            identifier: Identifier): AuthenticationTag =
    AuthenticationTag(hmac(key.toByteVector, identifier.toByteVector))

  override def authenticate(authentication: AuthenticationTag,
                            maybeVerificationKeyId: Option[VerificationKeyId],
                            identifier: Identifier): AuthenticationTag =
    AuthenticationTag(
      hmac(authentication.toByteVector,
           maybeVerificationKeyId
             .map(_.toByteVector)
             .getOrElse(ByteVector.empty) ++ identifier.toByteVector))

  override def encrypt(
      authentication: AuthenticationTag,
      rootKey: RootKey /* TODO differently? */ ): VerificationKeyId =
    new XChaCha20Poly1305(authentication.toByteVector.toArray)
      .encrypt(rootKey.toByteVector.toArray, Array.empty)
      .pipe(b => VerificationKeyId(ByteVector(b)))

  override def decrypt(authentication: AuthenticationTag,
                       verificationKeyId: VerificationKeyId): RootKey =
    new XChaCha20Poly1305(authentication.toByteVector.toArray)
      .decrypt(verificationKeyId.toByteVector.toArray, Array.empty)
      .pipe(b => RootKey(ByteVector(b)))

  private def hash(value: ByteVector): ByteVector =
    MessageDigest
      .getInstance("SHA-256")
      .digest(value.toArray)
      .pipe(ByteVector(_))

  override def bind(discharging: AuthenticationTag,
                    authorizing: AuthenticationTag): Seal =
    hash(discharging.toByteVector ++ authorizing.toByteVector).pipe(Seal.apply)
}
