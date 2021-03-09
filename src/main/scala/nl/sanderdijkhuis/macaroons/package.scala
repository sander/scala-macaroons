package nl.sanderdijkhuis

import cats.effect._
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import fs2.Stream
import io.estatico.newtype.macros.newtype
import nl.sanderdijkhuis.macaroons.Capability.{
  AuthenticationTag,
  Marshalling,
  Seal
}
import nl.sanderdijkhuis.macaroons.Varint.Offset
import tsec.common._

import java.net.URI
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.annotation.tailrec
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

  // https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt
  implicit object MacaroonMarshalling extends Marshalling[MacaroonV2] {

    private val endOfSection = Array(0.toByte)
    private val endOfSectionTag = 0
    private val locationTag = 1
    private val identifierTag = 2
    private val verificationIdTag = 4
    private val signatureTag = 6

    private val versionNumber = 2
    private val version = Array(versionNumber.toByte)

    private def field(fieldType: Int, content: Array[Byte]): Array[Byte] =
      Varint.encode(fieldType) ++ Varint.encode(content.length) ++ content

    private def optionalLocation(macaroon: Capability[MacaroonV2]) =
      macaroon.maybeLocation.toList
        .flatMap(loc => field(locationTag, loc.toURI.toString.getBytes))
        .toArray

    private def optionalLocation(caveat: Caveat) =
      caveat.maybeLocation.toList
        .flatMap(loc => field(locationTag, loc.toURI.toString.getBytes))
        .toArray

    private def optionalVerificationKeyId(caveat: Caveat) =
      caveat.maybeVerificationKeyId.toList
        .flatMap(vid => field(verificationIdTag, vid.toByteArray))
        .toArray

    private def identifier(macaroon: Capability[MacaroonV2]) =
      field(identifierTag, macaroon.identifier.toByteArray)

    private def identifier(caveat: Caveat) =
      field(identifierTag, caveat.identifier.toByteArray)

    private def signature(macaroon: Capability[MacaroonV2]) =
      field(signatureTag, macaroon.authentication.toByteArray)

    private def caveats(macaroon: Capability[MacaroonV2]) =
      macaroon.caveats.reverse
        .flatMap(c =>
          optionalLocation(c) ++ identifier(c) ++ optionalVerificationKeyId(c) ++ endOfSection)
        .toArray

    override def marshall(macaroon: Capability[MacaroonV2]): MacaroonV2 =
      MacaroonV2(
        version ++ optionalLocation(macaroon) ++ identifier(macaroon) ++ endOfSection ++ caveats(
          macaroon) ++ endOfSection ++ signature(macaroon))

    override def marshall(bound: Capability.Bound[MacaroonV2]): MacaroonV2 =
      ???

    override def unmarshallMacaroon(
        value: MacaroonV2): Option[Capability[MacaroonV2]] = {

      case class Tag(toInt: Int)
      case class Length(toInt: Int)
      case class Value(toByteArray: Array[Byte])

      def readTagLengthValueOrEndOfSection(
          in: Array[Byte],
          offset: Offset): Option[(Tag, Value, Offset)] = {
        for {
          (tag, offset) <- Varint.decodeToInt(in, offset)
          _ <- Option.when(tag != endOfSectionTag)(())
          (length, offset) <- Varint.decodeToInt(in, offset)
          end = offset.toInt + length
          value <- Option.when(end <= in.length)(in.slice(offset.toInt, end))
        } yield (Tag(tag), Value(value), Offset(end))
      }

      def parse(in: Array[Byte]): Option[Capability[MacaroonV2]] =
        for {
          _ <- in.headOption.map(_.toInt).filter(_ == versionNumber)
          (tag, value, offset) <- readTagLengthValueOrEndOfSection(
            in,
            Varint.Offset(1))
          location <- tag match {
            case Tag(t) if t == locationTag =>
              Some(Some(Location(new URI(new String(value.toByteArray)))))
            case _ => Some(None)
          }
          (id, offset) <- location match {
            case Some(_) =>
              readTagLengthValueOrEndOfSection(in, offset).collect {
                case (t, v, o) if t == Tag(identifierTag) =>
                  (Identifier(v.toByteArray), o)
              }
            case None => Some((Identifier(value.toByteArray), offset))
          }
          offset <- Option.when(
            in.length > offset.toInt && in(offset.toInt) == endOfSectionTag)(
            Offset(offset.toInt + 1))
        } yield
          Capability[MacaroonV2](location,
                                 id,
                                 List.empty,
                                 AuthenticationTag(Array.empty))(
            MacaroonCryptography,
            MacaroonMarshalling)

      val s = Stream(value.toByteArray: _*)

//      val x = for {
//        v <- s.head if v == versionNumber.toByte
//        r <- s.tail.through(x => x.take(3))
//      } yield ()

      parse(value.toByteArray)
    }

    override def unmarshallBound(
        value: MacaroonV2): Option[Capability.Bound[MacaroonV2]] = ???
  }
}
