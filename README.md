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
// key: MacSigningKey[HMACSHA256] = javax.crypto.spec.SecretKeySpec@fa77c70a
val macaroon = macaroons.service.mint(id, key).unsafeRunSync()
// macaroon: Macaroon = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(8 bytes, 0x70686f746f313233),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x726c7cbdce1e9bb729fa5b108a3e78f6ec82a4b8a528edbfada09ea02f6c62ac)
// )
```

We can serialize it to transfer it to the client:

```scala
macaroonV2.encode(macaroon).require.toBase64
// res0: String = "AgIIcGhvdG8xMjMAAAYgcmx8vc4em7cp+lsQij549uyCpLilKO2/raCeoC9sYqw="
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
//   tag = ByteVector(32 bytes, 0x9bf92ca731b7051f20a97aba96bcf4a5f584781642c9ac4860f859488db3d060)
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

TODO

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
