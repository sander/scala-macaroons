# Macaroons for Scala

This library implements [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://research.google/pubs/pub41892/), which are [inexplicably underused](https://latacora.micro.blog/a-childs-garden/), for [Scala](https://www.scala-lang.org/).

It uses the [libmacaroons version 2 binary format](https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt) with HMAC-SHA256 for authenticating macaroons, SHA256 for binding them, and XChaCha20-Poly1305 for encrypting verification keys.

> **Note**: Not ready for production use yet.

## Getting started

### Depending on Macaroons for Scala

Add to `build.sbt`:

```scala
dependsOn(
  ProjectRef(
    uri("git://github.com/sander/scala-macaroons.git#main"),
    "core"))
```

Import language dependencies:

```scala
import cats.effect._
import cats.effect.concurrent._
import cats.implicits._
import eu.timepit.refined.auto._
```

Import cryptography functions:

```scala
import tsec.mac.jca._
```

Import macaroons dependencies:

```scala
import nl.sanderdijkhuis.macaroons.codecs._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.modules._
```

### Baking macaroons

Say we run a photo service and we want to use macaroons to manage authorizations.

First, we specify how to generate locally unique identifiers, how to protect root keys, and how to make and verify assertions:

```scala
val macaroons: Macaroons[IO] = Macaroons.make()
```

Now we can mint a new macaroon:

```scala
val id       = Identifier.from("photo123")
// id: Identifier = ByteVector(8 bytes, 0x70686f746f313233)
val key      = HMACSHA256.generateKey[IO].unsafeRunSync()
// key: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@58866cc
val macaroon = macaroons.service.mint(id)(key).unsafeRunSync()
// macaroon: Macaroon = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(8 bytes, 0x70686f746f313233),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0xcaeff6309c7a58162bd851927214c780247d5a138183e9b2a058f76056911baa)
// )
```

We can serialize it to transfer it to the client:

```scala
macaroonV2.encode(macaroon).require.toBase64
// res0: String = "AgIIcGhvdG8xMjMAAAYgyu/2MJx6WBYr2FGSchTHgCR9WhOBg+myoFj3YFaRG6o="
```

Now, when the client would get back to us with this macaroon, we could verify it:

```scala
macaroons.service.verify(macaroon, key).unsafeRunSync()
// res1: Boolean = true
```

### Adding caveats

Before sharing the macaroon with the user, we can attenuate the access:

```scala
val dateBeforeApril18 = Predicate.from("date < 2021-04-18")
val userIsWilleke     = Predicate.from("user = willeke")

val transformation = {
  import macaroons.caveats._
  attenuate(dateBeforeApril18) *> attenuate(userIsWilleke)
}
```

And add these extra layers to the macaroon:

```scala
val macaroon2 = transformation.runS(macaroon).unsafeRunSync()
// macaroon2: Macaroon = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(8 bytes, 0x70686f746f313233),
//   caveats = Vector(
//     Caveat(
//       maybeLocation = None,
//       identifier = ByteVector(17 bytes, 0x64617465203c20323032312d30342d3138),
//       maybeChallenge = None
//     ),
//     Caveat(
//       maybeLocation = None,
//       identifier = ByteVector(14 bytes, 0x75736572203d2077696c6c656b65),
//       maybeChallenge = None
//     )
//   ),
//   tag = ByteVector(32 bytes, 0xf4801386d51d33a64e673bd7f79b0c51b218c85fb6000905f4aa11bab2f2b247)
// )
```

Whenever a user makes a request with this macaroon, we can authorize the request by verifying the macaroon to a set of true predicates:

```scala
val predicatesForThisRequest =
  Set(dateBeforeApril18, userIsWilleke, Predicate.from("ip = 192.168.0.1"))
```

Note that although this particular example uses a set, we could have used any function `Predicate => Boolean`. One particularly useful type of function matches the prefix of the predicate (e.g. `date < `), parses the rest of the predicate and verifies this with data from the request context. 

To verify the macaroon, again:

```scala
macaroons.service.verify(macaroon2, key, predicatesForThisRequest)
  .unsafeRunSync()
// res2: Boolean = true
```

### Adding third-party caveats

Although we could have a verifier function query some external service as a side effect, macaroons offer a better way. On our photo service, we could confine a macaroon to be used only within a certain context, asserted by for example an authentication service. The confinement is again expressed as a caveat, containing a challenge to be resolved at the authentication service. This is proven using a *discharge macaroon* issued by the authentication service, which could in itself contain caveats.

To demonstrate this, first we will create a stub authentication service:

```scala
implicit val cs = IO.contextShift(scala.concurrent.ExecutionContext.global)
val caveatKey   = Deferred[IO, MacSigningKey[HMACSHA256]].unsafeRunSync()

val authentication = Context(
  Location("https://authentication.example/").some,
  (key: MacSigningKey[HMACSHA256], predicate) =>
    IO(assert(predicate == userIsWilleke)) *> caveatKey.complete(key) *>
      Identifier.from("discharge234").pure[IO]
)
```

This service takes a caveat key and a predicate generated by the client, and returns an identifier representing the challenge. In the stub, we hardcode the predicate and challenge, and remember the caveat key.

At the photo service, we mint a new macaroon and confine access to an authentication context where the user is Willeke:

```scala
val rootKey = HMACSHA256.generateKey[IO].unsafeRunSync()
// rootKey: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@588120e
val (macaroon, caveatId) =
  (macaroons.service.mint(Identifier.from("photo124"))(rootKey) >>=
    macaroons.caveats.confine(authentication, userIsWilleke).run)
    .unsafeRunSync()
// macaroon: Macaroon = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(8 bytes, 0x70686f746f313234),
//   caveats = Vector(
//     Caveat(
//       maybeLocation = Some(value = https://authentication.example/),
//       identifier = ByteVector(12 bytes, 0x646973636861726765323334),
//       maybeChallenge = Some(
//         value = ByteVector(72 bytes, 0x1d8db69f4f69266d52c4cbb8391ac4d687f970ced3e86223f9776ca423eb840c301c4b2534707cfcee54a237dbc47fd711756fbc8d6fb86d0270cad65eb923897cfe68aa41f8e14b)
//       )
//     )
//   ),
//   tag = ByteVector(32 bytes, 0xa716fa9dd10f885c28d4a59456862ef52ff504cfb067e4d0671a9bf0d9d0f01f)
// )
// caveatId: Identifier = ByteVector(12 bytes, 0x646973636861726765323334)
```

Now, in order to use this macaroon, Willeke needs to authenticate at the authentication service and mint the discharge macaroon there:

```scala
val discharge =
  (caveatKey.get >>=
    macaroons.service.mint(caveatId, authentication.maybeLocation))
    .unsafeRunSync()
// discharge: Macaroon = Macaroon(
//   maybeLocation = Some(value = https://authentication.example/),
//   id = ByteVector(12 bytes, 0x646973636861726765323334),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x81898d85744dd8b64e520a28c78caf8e332cf8c1fd38b9a30654429057a54b58)
// )
```

Before making a request to the photo service, she binds the discharge macaroon to the original one, altering its authentication tag:

```scala
val bound = macaroons.service.bind(macaroon, discharge).unsafeRunSync()
// bound: Macaroon = Macaroon(
//   maybeLocation = Some(value = https://authentication.example/),
//   id = ByteVector(12 bytes, 0x646973636861726765323334),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0xff4773cc77054aff219af3c1cbae1c42b5bf3af5510e139d5526bf29ddbd7285)
// )
```

And the photo service can verify this pair of macaroons:

```scala
macaroons.service.verify(macaroon, rootKey, Set.empty, Set(bound))
  .unsafeRunSync()
// res3: Boolean = true
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
