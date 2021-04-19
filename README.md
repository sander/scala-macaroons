# Macaroons for Scala

This library implements [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://research.google/pubs/pub41892/), which are [inexplicably underused](https://latacora.micro.blog/a-childs-garden/), for [Scala](https://www.scala-lang.org/).

It uses the [libmacaroons binary format](https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt) with HMAC-SHA256 for authenticating macaroons, SHA256 for binding them, and XChaCha20-Poly1305 for encrypting verification keys.

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

Import macaroons dependencies:

```scala
import nl.sanderdijkhuis.macaroons.codecs._
import nl.sanderdijkhuis.macaroons.effects._
import nl.sanderdijkhuis.macaroons.domain._
import nl.sanderdijkhuis.macaroons.modules._
import nl.sanderdijkhuis.macaroons.repositories._
```

### Baking macaroons

Say we run a photo service and we want to use macaroons to manage authorizations.

First, we specify how to generate locally unique identifiers, how to protect root keys, and how to make and verify assertions:

```scala
val identifiers: Identifiers[IO] = Identifiers.secureRandom
val rootKeys: RootKeys[IO]       = RootKeys.makeInMemory().unsafeRunSync()
val assertions: Assertions[IO]   = Assertions.make(rootKeys.repository)
```

Now we can mint a new macaroon:

```scala
val macaroon = assertions.service.assert().unsafeRunSync()
// macaroon: Macaroon with Authority = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(16 bytes, 0xaf2e6c59ea2e282e5ad29dda68b9fc5f),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x5427883e0667957e67b32979c0e75d0009e20ae4cf47d596af98731b1ac43699)
// )
```

We can serialize it to transfer it to the client:

```scala
macaroonV2.encode(macaroon).require.toBase64
// res0: String = "AgIQry5sWeouKC5a0p3aaLn8XwAABiBUJ4g+BmeVfmezKXnA510ACeIK5M9H1ZavmHMbGsQ2mQ=="
```

Now, when the client would get back to us with this macaroon, we could verify it:

```scala
assertions.service.verify(macaroon).unsafeRunSync()
// res1: Boolean = true
```

### Adding caveats

Before sharing the macaroon with the user, we can attenuate the access:

```scala
val dateBeforeApril18 = Predicate.from("date < 2021-04-18")
val userIsWilleke     = Predicate.from("user = willeke")

val transformation = {
  import assertions.macaroons.caveats._
  attenuate(dateBeforeApril18) *> attenuate(userIsWilleke)
}
```

And bake a macaroon with this transformation:

```scala
val macaroon2 = transformation.runS(macaroon).unsafeRunSync()
// macaroon2: Macaroon with Authority = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(16 bytes, 0xaf2e6c59ea2e282e5ad29dda68b9fc5f),
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
//   tag = ByteVector(32 bytes, 0xd091a398a4c2c840fb39fb88b28f899f6c88efbfa6f450c766ecf5b748bf5e34)
// )
```

Whenever a user makes a request with this macaroon, we can authorize the request by verifying the macaroon to a set of true predicates:

```scala
val someOtherPredicate = Predicate.from("ip = 192.168.0.1")
val predicatesForThisRequest =
  Set(dateBeforeApril18, userIsWilleke, someOtherPredicate)
```

Note that although we are using a set, we can use any function `Predicate => Boolean`. To verify, again:

```scala
assertions.service.verify(macaroon2, predicatesForThisRequest).unsafeRunSync()
// res2: Boolean = true
```

### Adding third-party caveats

TODO

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
