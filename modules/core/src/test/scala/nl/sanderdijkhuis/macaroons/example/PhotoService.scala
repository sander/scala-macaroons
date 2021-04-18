package nl.sanderdijkhuis.macaroons.example

import cats.implicits._
import nl.sanderdijkhuis.macaroons.effects.Identifiers
import nl.sanderdijkhuis.macaroons.modules.Macaroons
import nl.sanderdijkhuis.macaroons.services.CaveatService.Transformation
import tsec.cipher.symmetric.bouncy.XChaCha20Poly1305
import tsec.mac.jca.HMACSHA256

object PhotoService {

  // Say we run a photo service.
  //
  // Specify a strategy to generate macaroon and caveat identifiers unique at
  // this photo service:

  import cats.effect._
  import nl.sanderdijkhuis.macaroons.domain.macaroon._

  val generateIdentifier: IO[Identifier] = Identifiers[IO].make()

  // Then specify a strategy to store root keys, to generate and verify
  // macaroons:

  import nl.sanderdijkhuis.macaroons.repositories._
  import nl.sanderdijkhuis.macaroons.services.MacaroonService.RootKey
  import nl.sanderdijkhuis.macaroons.services._

  val rootKeyRepository: KeyRepository[IO, Identifier, RootKey] = KeyRepository
    .inMemoryRef[IO, Identifier, RootKey](generateIdentifier).unsafeRunSync()

  // The same for discharge keys, to generate discharges for third-party
  // caveats:
  val dischargeKeyRepository
      : KeyRepository[IO, Identifier, (RootKey, Predicate)] = KeyRepository
    .inMemoryRef[IO, Identifier, (RootKey, Predicate)](generateIdentifier)
    .unsafeRunSync()

  // Now make the principal to represent our photo service:

  import eu.timepit.refined.auto._

  val location: Location = Location("https://photos.example/")

  val M: Macaroons[IO] = Macaroons
    .make[IO, Throwable](XChaCha20Poly1305.defaultIvGen[IO].genIv)

  val assertions: AssertionService[IO] = AssertionService
    .make[IO, Throwable, HMACSHA256, XChaCha20Poly1305](Some(location))(
      M.service,
      rootKeyRepository,
      HMACSHA256.generateKey[IO])

  // With this principal we can create new macaroons:

  val m1: Macaroon with Authority = assertions.assert().unsafeRunSync()

  // Or macaroons with caveats:

  val attenuation: Transformation[IO, Unit] = M.caveats
    .attenuate(Predicate(Identifier.from("date < 2021-04-18"))) *>
    M.caveats.attenuate(Predicate(Identifier.from("user = willeke")))

  val m2: Macaroon with Authority = assertions.assert()
    .flatMap(attenuation.runS).unsafeRunSync()

  println(m2)

  // Use the codec to transfer it to the client:

  import nl.sanderdijkhuis.macaroons.codecs.macaroon._

  println(macaroonV2.encode(m2).require.toBase64)

  def main(args: Array[String]): Unit = ()
}
