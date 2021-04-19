package nl.sanderdijkhuis.macaroons.example

object PhotoService {

  // Say we run a photo service.
  //
  // Specify a strategy to generate macaroon and caveat identifiers unique at
  // this photo service:

  import cats.effect._
  import nl.sanderdijkhuis.macaroons.domain.macaroon._
  import nl.sanderdijkhuis.macaroons.effects._

  val generateIdentifier: IO[Identifier] = Identifiers[IO].make()

  // Then specify a strategy to store root keys, to generate and verify
  // macaroons:

  import nl.sanderdijkhuis.macaroons.repositories._
  import nl.sanderdijkhuis.macaroons.services.MacaroonService.RootKey

  val rootKeyRepository: KeyRepository[IO, Identifier, RootKey] = KeyRepository
    .inMemoryRef[IO, Identifier, RootKey](generateIdentifier).unsafeRunSync()

  // The same for discharge keys, to generate discharges for third-party
  // caveats:
  val dischargeKeyRepository
      : KeyRepository[IO, Identifier, (RootKey, Predicate)] = KeyRepository
    .inMemoryRef[IO, Identifier, (RootKey, Predicate)](generateIdentifier)
    .unsafeRunSync()

  // Now make the principal modules to represent our photo service:

  import eu.timepit.refined.auto._
  import nl.sanderdijkhuis.macaroons.modules._
  import tsec.mac.jca._

  val location: Location = Location("https://photos.example/")
  val M: Macaroons[IO]   = Macaroons.make()
  val A: Assertions[IO]  = Assertions.make(Some(location), M, rootKeyRepository)

  // With this principal we can create new macaroons:

  val m1: Macaroon with Authority = A.service.assert().unsafeRunSync()

  // Or macaroons with caveats:

  import cats.implicits._

  val dateBeforeApril18: Predicate =
    Predicate(Identifier.from("date < 2021-04-18"))
  val userIsWilleke: Predicate = Predicate(Identifier.from("user = willeke"))

  val attenuation: Transformation[IO, Unit] = M.caveats
    .attenuate(dateBeforeApril18) *> M.caveats.attenuate(userIsWilleke)

  val m2: Macaroon with Authority = A.service.assert().flatMap(attenuation.runS)
    .unsafeRunSync()

  println(m2)

  // Use the codec to transfer it to the client:

  import nl.sanderdijkhuis.macaroons.codecs.macaroon._

  println(macaroonV2.encode(m2).require.toBase64)

  def main(args: Array[String]): Unit = ()
}
