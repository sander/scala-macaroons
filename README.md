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
// key: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@fa77c966
val macaroon = macaroons.service.mint(id)(key).unsafeRunSync()
// macaroon: Macaroon = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(8 bytes, 0x70686f746f313233),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x6f8e443bcc4c6d3225b72995a8288c1e3ea7cdb296261e260728f01b1ef44f79)
// )
```

We can serialize it to transfer it to the client:

```scala
macaroonV2.encode(macaroon).require.toBase64
// res0: String = "AgIIcGhvdG8xMjMAAAYgb45EO8xMbTIltymVqCiMHj6nzbKWJh4mByjwGx70T3k="
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
//   tag = ByteVector(32 bytes, 0xafd90e314a97c37e988835c464b51c486f82195adb3a235b99319dcb4376e860)
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
// rootKey: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@fa77c81c
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
//         value = ByteVector(72 bytes, 0x91c362b136ee7c87baa02c1fa9bf77deb15180206973f53ab61a91343e730a676028d610e77b0b86c2000425ba711fa367e20f1c28bce8aea3d12009003fbd42714103cb88a69583)
//       )
//     )
//   ),
//   tag = ByteVector(32 bytes, 0xd83ee662f501d67c200ae854fb5c9fcceb7ec60b5b82dd14e2beb3c61b48ead9)
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
//   tag = ByteVector(32 bytes, 0xe297c4ad1ec32698f9288d2ffef81be17fb21f81a892f58858c006953ed81eb7)
// )
```

When making a request to the photo service, she binds the discharge macaroon to the original one:

```scala
val bound = macaroons.service.bind(macaroon, discharge).unsafeRunSync()
// bound: Macaroon = Macaroon(
//   maybeLocation = Some(value = https://authentication.example/),
//   id = ByteVector(12 bytes, 0x646973636861726765323334),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x07f7ad9739af3b9caa65dddfe00ca4606c96aefa5ac6aeb33da8744479de3d74)
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
