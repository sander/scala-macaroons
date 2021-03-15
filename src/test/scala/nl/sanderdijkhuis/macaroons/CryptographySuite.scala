package nl.sanderdijkhuis.macaroons

import cats.effect.IO
import com.google.crypto.tink.{
  BinaryKeysetWriter,
  CleartextKeysetHandle,
  JsonKeysetWriter,
  KeysetHandle,
  Mac
}
import com.google.crypto.tink.config.TinkConfig
import com.google.crypto.tink.mac.{HmacKeyManager, MacConfig}
import weaver._

import java.io.File
import java.util.Base64

object CryptographySuite extends SimpleIOSuite {

  pureTest("foo") {

    // trying with tink. might be easier to just keep keys
    // as bytevectors and persist them like that as well.
//    case class RootKey[Mac](mac: Mac)
//    case class RootKey2[F[_]: Mac]()
//    case class RootKey3[F[_]](mac: Mac[F])
//    case class Macaroon[RootKey](rootKey: RootKey)

    MacConfig.register()

    val template = HmacKeyManager.hmacSha256Template()
    val handle = KeysetHandle.generateNew(template)

    val primitive = handle.getPrimitive(classOf[Mac]) // would be RootKey instance
    val ciphertext = primitive.computeMac("hello".getBytes("utf-8"))
    println(Base64.getEncoder.encodeToString(ciphertext))

    val fileName = "my-keyset.json"
    CleartextKeysetHandle.write(handle,
                                JsonKeysetWriter.withFile(new File(fileName)))

    CleartextKeysetHandle.write(handle,
                                JsonKeysetWriter.withFile(new File(fileName)))

    CleartextKeysetHandle.write(handle,
                                BinaryKeysetWriter.withFile(new File(fileName)))

    expect(true)
  }
}
