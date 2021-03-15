package nl.sanderdijkhuis.macaroons

import cats.effect.Sync
import cats.implicits._
import com.google.crypto.tink.mac.{HmacKeyManager, MacConfig}
import com.google.crypto.tink.{KeysetHandle, Mac}
import io.estatico.newtype.macros.newtype
import scodec.bits.ByteVector

import scala.language.implicitConversions

trait RootKeyManagement[F[_], RootKey] {

  def generate(): F[RootKey]

  def protect(key: RootKey, assertion: Option[Identifier]): F[Identifier]
  def recover(identifier: Identifier): F[(RootKey, Option[Identifier])]

  // move to own typeclass? to also allow for verification keys
  def authenticate(key: RootKey, identifier: Identifier): F[Authentication]
//  def encrypt(authentication: Authentication, key: Key): F[Challenge]
//  def decrypt(authentication: Authentication, challenge: Challenge): F[Key]
}

object RootKeyManagement {

  trait OtherKeyManagement[F[_], OtherKey] {
    def generate(): F[OtherKey]
    def encrypt(authentication: Authentication, key: OtherKey): F[Challenge]
    def decrypt(authentication: Authentication,
                challenge: Challenge): F[OtherKey]
  }

//  trait OtherPrincipal[F[_], Key] {
//    def prepare(key: Key, identifier: Identifier): F[Identifier]
//  }

  @newtype case class TinkRootKey(toKeySetHandle: KeysetHandle)

  class TinkKeyManagement[F[_]: Sync]
      extends RootKeyManagement[F, TinkRootKey] {

    MacConfig.register()

    override def generate(): F[TinkRootKey] = {
      val template = HmacKeyManager.hmacSha256Template()
      Sync[F].delay(KeysetHandle.generateNew(template)).map(TinkRootKey(_))
    }

    override def protect(key: TinkRootKey,
                         assertion: Option[Identifier]): F[Identifier] =
      ???

    override def recover(
        identifier: Identifier): F[(TinkRootKey, Option[Identifier])] = ???

    override def authenticate(key: TinkRootKey,
                              identifier: Identifier): F[Authentication] =
      Sync[F]
        .delay(key.toKeySetHandle.getPrimitive(classOf[Mac]))
        .map(_.computeMac(identifier.toByteVector.toArray))
        .map(b => Authentication(ByteVector(b)))
  }
}
