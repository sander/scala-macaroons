package nl.sanderdijkhuis

import cats._
import cats.effect._
import cats.implicits._
import fs2.Stream
import io.estatico.newtype.macros.newtype
import nl.sanderdijkhuis.macaroons4s.Capability.{
  AuthenticationTag,
  Marshalling,
  Seal
}
import tsec.cipher.symmetric.bouncy.BouncySecretKey
import tsec.common._
import tsec.mac.jca._
import tsec.common._
import tsec.cipher.symmetric._
import cats.effect.IO
import com.google.crypto.tink.{Aead, DeterministicAead, KeysetHandle}
import com.google.crypto.tink.aead.{AeadConfig, XChaCha20Poly1305KeyManager}
import com.google.crypto.tink.subtle.XChaCha20Poly1305

import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._
import scala.annotation.tailrec

package object macaroons4s {

  @newtype case class Location(toURI: URI) {

    override def toString: String = toURI.toString
  }

  @newtype case class Identifier(toByteArray: Array[Byte]) {

    override def toString: String = new String(toByteArray)
  }

  @newtype case class VerificationKeyId(toByteArray: Array[Byte]) {

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

    private def hmac(key: Array[Byte], message: Array[Byte]): Array[Byte] = {
      val algorithm = "HmacSHA256"
      val mac = Mac.getInstance(algorithm)
      val spec = new SecretKeySpec(key, algorithm)
      mac.init(spec)
      mac.doFinal(message)
    }

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

  // https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt
  implicit object Marshalling extends Marshalling[MacaroonV2] {

    private def marshall(caveat: Caveat): List[String] =
      List(caveat.identifier.toString) ++ caveat.maybeVerificationKeyId.toList
        .map(vid => s"vid $vid") ++ caveat.maybeLocation.toList
        .map(loc => s"location $loc")

    private def version = Array(2.toByte)

    private def field(fieldType: Int, content: Array[Byte]): Array[Byte] =
      Varint.encode(fieldType) ++ Varint.encode(content.length) ++ content

    private def optionalLocation(macaroon: Capability[MacaroonV2]) =
      macaroon.maybeLocation.toList
        .flatMap(loc => field(1, loc.toURI.toString.getBytes))
        .toArray

    private def optionalLocation(caveat: Caveat) =
      caveat.maybeLocation.toList
        .flatMap(loc => field(1, loc.toURI.toString.getBytes))
        .toArray

    private def optionalVerificationKeyId(caveat: Caveat) =
      caveat.maybeVerificationKeyId.toList
        .flatMap(vid => field(4, vid.toByteArray))
        .toArray

    private def identifier(macaroon: Capability[MacaroonV2]) =
      field(2, macaroon.identifier.toByteArray)

    private def identifier(caveat: Caveat) =
      field(2, caveat.identifier.toByteArray)

    private def endOfSection = Array(0.toByte)

    private def signature(macaroon: Capability[MacaroonV2]) =
      field(6, macaroon.authentication.toByteArray)

    private def caveats(macaroon: Capability[MacaroonV2]) =
      macaroon.caveats.reverse
        .flatMap(c =>
          optionalLocation(c) ++ identifier(c) ++ optionalVerificationKeyId(c) ++ endOfSection)
        .toArray

    override def marshall(macaroon: Capability[MacaroonV2]): MacaroonV2 =
      MacaroonV2(
        version ++ optionalLocation(macaroon) ++ identifier(macaroon) ++ endOfSection ++ caveats(
          macaroon) ++ endOfSection ++ signature(macaroon))
//        (List("2") ++ macaroon.maybeLocation.toList
//          .map(loc => s"location $loc") ++ List(
//          s"identifier ${macaroon.identifier}") ++ macaroon.caveats
//          .flatMap(marshall))
//          .mkString("\n")
//          .getBytes
//          .pipe(MacaroonV2(_))

    override def marshall(bound: Capability.Bound[MacaroonV2]): MacaroonV2 =
      ???

    override def unmarshallMacaroon(
        value: MacaroonV2): Option[Capability[MacaroonV2]] = ???

    override def unmarshallBound(
        value: MacaroonV2): Option[Capability.Bound[MacaroonV2]] = ???
  }
}
