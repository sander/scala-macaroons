package nl.sanderdijkhuis.macaroons

import cats.Monad
import cats.effect.{IO, LiftIO, Sync, SyncIO}
import cats.implicits._
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import scodec.bits.{ByteVector, HexStringSyntax}
import tsec.cipher.symmetric.{
  AuthEncryptor,
  CipherText,
  Iv,
  IvGen,
  PlainText,
  RawCipherText
}
import tsec.cipher.symmetric.bouncy.{BouncySecretKey, XSalsa20Poly1305}
import tsec.common.SecureRandomId

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.util.chaining._

trait KeyManagement[F[_]] {

  def generateRootKey(): F[RootKey]

//  def authenticateAssertion(key: RootKey, identifier: Identifier): F[Tag]
//
//  /**
//    * Has effects since encryption is often not deterministic.
//    */
//  def encryptCaveatRootKey(authentication: Tag, rootKey: RootKey): F[Challenge]
//
//  def decryptCaveatRootKey(authentication: Tag,
//                           challenge: Challenge): F[RootKey]

}

object KeyManagement {

//  def apply[F[_]](implicit cryptography: KeyManagement[F]): KeyManagement[F] =
//    cryptography

  class Live[F[_]: Sync]() extends KeyManagement[F] {
    override def generateRootKey(): F[RootKey] =
      SecureRandomId.Strong.generateF.flatMap(b =>
        Sync[F].delay(RootKey.from(b.getBytes).get))
  }

  def apply[F[_]: Sync]: KeyManagement[F] = new Live()
//
//  implicit def hmacSHA256AndXChaCha20Poly1305[F[_]: Sync]: KeyManagement[F] =
//    new KeyManagement[F] {
//
//      override def generateRootKey(): F[RootKey] = ???
//    }
}
