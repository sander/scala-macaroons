package nl.sanderdijkhuis

import cats.effect._
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import fs2.Stream
import io.estatico.newtype.macros.newtype
import nl.sanderdijkhuis.macaroons.Capability.{AuthenticationTag, Seal}
import tsec.common._

import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

package object macaroons {

  sealed trait Field

  case class Location(toURI: URI) extends Field {

    override def toString: String = toURI.toString
  }

  case class Identifier(toByteArray: Array[Byte]) extends Field {

    override def toString: String = new String(toByteArray)
  }

  case class VerificationKeyId(toByteArray: Array[Byte]) extends Field {

    override def toString: String = new String(toByteArray)
  }

  @newtype case class RootKey private (toByteArray: Array[Byte])
  object RootKey {

    def stream[F[_]: Sync]: Stream[F, RootKey] =
      for {
        m <- Stream.eval[F, ManagedRandom](Sync[F].delay(new ManagedRandom {}))
        k <- Stream
          .eval[F, Array[Byte]](
            Sync[F].delay(new Array[Byte](32).tap(m.nextBytes)))
          .repeat
      } yield RootKey(k)
  }

  @newtype case class MacaroonV2(toByteArray: Array[Byte]) {

    def toBase64url: String =
      Base64.getUrlEncoder.withoutPadding.encodeToString(toByteArray)
  }

  implicit object MacaroonCryptography extends Cryptography[MacaroonV2] {

    private val algorithm = "HmacSHA256"

    private def hmac(key: Array[Byte], message: Array[Byte]): Array[Byte] =
      Mac
        .getInstance(algorithm)
        .tap(_.init(new SecretKeySpec(key, algorithm)))
        .doFinal(message)

    override def authenticate(
        key: RootKey,
        identifier: Identifier): Capability.AuthenticationTag =
      AuthenticationTag(hmac(key.toByteArray, identifier.toByteArray))

    override def authenticate(
        authentication: Capability.AuthenticationTag,
        maybeVerificationKeyId: Option[VerificationKeyId],
        identifier: Identifier): Capability.AuthenticationTag =
      AuthenticationTag(
        hmac(authentication.toByteArray,
             maybeVerificationKeyId
               .map(_.toByteArray)
               .getOrElse(Array.emptyByteArray) ++ identifier.toByteArray))

    override def encrypt(
        authentication: Capability.AuthenticationTag,
        rootKey: RootKey /* TODO differently? */ ): VerificationKeyId =
      new XChaCha20Poly1305(authentication.toByteArray)
        .encrypt(rootKey.toByteArray, Array.empty)
        .pipe(VerificationKeyId.apply)

    override def decrypt(authentication: Capability.AuthenticationTag,
                         verificationKeyId: VerificationKeyId): RootKey =
      new XChaCha20Poly1305(authentication.toByteArray)
        .decrypt(verificationKeyId.toByteArray, Array.empty)
        .pipe(RootKey.apply)

    private def hash(value: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("SHA-256").digest(value)

    override def bind(
        discharging: Capability.AuthenticationTag,
        authorizing: Capability.AuthenticationTag): Capability.Seal =
      hash(discharging.toByteArray ++ authorizing.toByteArray).pipe(Seal.apply)
  }
}
