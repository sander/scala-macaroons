package nl.sanderdijkhuis.macaroons

//noinspection TypeAnnotation
object Example {

  import cats.effect._
  import cats.effect.concurrent._
  import cats.implicits._
  import eu.timepit.refined.auto._

  import tsec.mac.jca._

  import nl.sanderdijkhuis.macaroons.codecs._
  import nl.sanderdijkhuis.macaroons.domain._
  import nl.sanderdijkhuis.macaroons.modules._

  val macaroons: Macaroons[IO] = Macaroons.make()

  val id       = Identifier.from("photo123")
  val key      = HMACSHA256.generateKey[IO].unsafeRunSync()
  val macaroon = macaroons.service.mint(id)(key).unsafeRunSync()

  macaroonV2.encode(macaroon).require.toBase64

  macaroons.service.verify(macaroon, key).unsafeRunSync()

  val dateBeforeApril18 = Predicate.from("date < 2021-04-18")
  val userIsWilleke     = Predicate.from("user = willeke")

  val transformation = {
    import macaroons.caveats._
    attenuate(dateBeforeApril18) *> attenuate(userIsWilleke)
  }

  val macaroon2 = transformation.runS(macaroon).unsafeRunSync()

  val predicatesForThisRequest =
    Set(dateBeforeApril18, userIsWilleke, Predicate.from("ip = 192.168.0.1"))

  macaroons.service.verify(macaroon2, key, predicatesForThisRequest)
    .unsafeRunSync()

//  val contextShift = IO.contextShift()
  implicit val cs = IO.contextShift(scala.concurrent.ExecutionContext.global)
  val caveatKey   = Deferred[IO, MacSigningKey[HMACSHA256]].unsafeRunSync()

  val authentication = Context(
    Location("https://authentication.example/").some,
    (key: MacSigningKey[HMACSHA256], predicate) =>
      IO(assert(predicate == userIsWilleke)) *> caveatKey.complete(key) *>
        Identifier.from("discharge234").pure[IO]
  )

  object Second {

    val rootKey = HMACSHA256.generateKey[IO].unsafeRunSync()

    val (macaroon, caveatId) =
      (macaroons.service.mint(Identifier.from("photo124"))(rootKey) >>=
        macaroons.caveats.confine(authentication, userIsWilleke).run)
        .unsafeRunSync()

    val discharge =
      (caveatKey.get >>=
        macaroons.service.mint(caveatId, authentication.maybeLocation))
        .unsafeRunSync()

    val bound = macaroons.service.bind(macaroon, discharge).unsafeRunSync()

    println(
      macaroons.service.verify(macaroon, rootKey, Set.empty, Set(bound))
        .unsafeRunSync())
  }

  def main(args: Array[String]): Unit = println(Second)
}
