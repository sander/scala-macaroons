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
// key: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@588250e
val macaroon = macaroons.service.mint(id)(key).unsafeRunSync()
// macaroon: Macaroon = Macaroon(None,ByteVector(8 bytes, 0x70686f746f313233),Vector(),ByteVector(32 bytes, 0x7f9273e144fb94ced8c6f5e5cd1f65e273eca6db44dc395a249daa8049318fe0))
```

We can serialize it to transfer it to the client:

```scala
macaroonV2.encode(macaroon).require.toBase64
// res0: String = "AgIIcGhvdG8xMjMAAAYgf5Jz4UT7lM7YxvXlzR9l4nPspttE3DlaJJ2qgEkxj+A="
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
// macaroon2: Macaroon = Macaroon(None,ByteVector(8 bytes, 0x70686f746f313233),Vector(Caveat{date < 2021-04-18}, Caveat{user = willeke}),ByteVector(32 bytes, 0x7837ec50b517ef3e8ae12948721cde0579ef863eaa5c99fb6042f4c27a613f53))
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
// rootKey: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@5882283
val (macaroon, caveatId) =
  (macaroons.service.mint(Identifier.from("photo124"))(rootKey) >>=
    macaroons.caveats.confine(authentication, userIsWilleke).run)
    .unsafeRunSync()
// macaroon: Macaroon = Macaroon(None,ByteVector(8 bytes, 0x70686f746f313234),Vector(Caveat{https://authentication.example/,discharge234,ByteVector(72 bytes, 0xb0649b7edca9b09edad8523f29a64d1431163206edc970d5fe37e91df29bd41b30efec921f07369c0dedf8d94add361611d9c61007c888ef3c4b4881abfe77f7df083950b00b3697)}),ByteVector(32 bytes, 0x518e539dfe88489acd966141bbb74b4b0d364b3e98ec267a59941127bbc35503))
// caveatId: Identifier = ByteVector(12 bytes, 0x646973636861726765323334)
```

Now, in order to use this macaroon, Willeke needs to authenticate at the authentication service and mint the discharge macaroon there:

```scala
val discharge =
  (caveatKey.get >>=
    macaroons.service.mint(caveatId, authentication.maybeLocation))
    .unsafeRunSync()
// discharge: Macaroon = Macaroon(Some(https://authentication.example/),ByteVector(12 bytes, 0x646973636861726765323334),Vector(),ByteVector(32 bytes, 0x4493dee15a9ee9bfdd64d96e253dd38e8e5b4064c7e8cc67d770184150bb9e7c))
```

When making a request to the photo service, she binds the discharge macaroon to the original one:

```scala
val bound = macaroons.service.bind(macaroon, discharge).unsafeRunSync()
// bound: Macaroon = Macaroon(Some(https://authentication.example/),ByteVector(12 bytes, 0x646973636861726765323334),Vector(),ByteVector(32 bytes, 0x048896f694fdb8bb9bc8eb7db8d7afa39b7500677d0d11c5b7d5f4d3203dd4d9))
```

And the photo service can verify this pair of macaroons:

```scala
macaroons.service.verify(macaroon, rootKey, Set.empty, Set(bound))
  .unsafeRunSync()
// res3: Boolean = true
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
