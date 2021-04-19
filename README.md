# Macaroons for Scala

This library implements [Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud](https://research.google/pubs/pub41892/), which are [inexplicably underused](https://latacora.micro.blog/a-childs-garden/), for [Scala](https://www.scala-lang.org/).

It uses the [libmacaroons binary format](https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt) with HMAC-SHA256 for authenticating macaroons, SHA256 for binding them, and XChaCha20-Poly1305 for encrypting verification keys.

> **Note**: Not ready for production use yet.

## Getting started

### Adding `scala-macaroons` as a dependency

Add to `build.sbt`:

```scala
dependsOn(
  ProjectRef(
    uri("git://github.com/sander/scala-macaroons.git#main"),
    "core"))
```

### Baking macaroons

Say we run a photo service.

Import language dependencies:

```scala
import cats.effect._
import cats.implicits._
import eu.timepit.refined.auto._
```

Import macaroons dependencies:

```scala
import nl.sanderdijkhuis.macaroons.codecs.macaroon._
import nl.sanderdijkhuis.macaroons.effects._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.modules._
import nl.sanderdijkhuis.macaroons.repositories._
```

Specify a strategy to generate macaroon and caveat identifiers unique at this photo service:

```scala
val identifiers: Identifiers[IO] = Identifiers.secureRandom
```

Then specify a strategy to store root keys, to generate and verify macaroons:

```scala
val rootKeys: RootKeys[IO] = RootKeys.makeInMemory().unsafeRunSync()
```

Now make the principal module to represent our photo service:

```scala
val assertions: Assertions[IO] = Assertions.make(rootKeys.repository)
```

With this principal we can create new macaroons:

```scala
val m1: Macaroon with Authority = assertions.service.assert().unsafeRunSync()
// m1: Macaroon with Authority = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(16 bytes, 0x18d49160dc630726098b42516284aa09),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x59ad1a35bf3a2a6d62e361544a78a7490b0fe811df29d031dc181026dc5e6e29)
// )
```

Or define some caveats:

```scala
val dateBeforeApril18: Predicate = Predicate.from("date < 2021-04-18")
val userIsWilleke: Predicate     = Predicate.from("user = willeke")

val M: Macaroons[IO] = assertions.macaroons
val attenuation: Transformation[IO, Unit] =
  M.caveats.attenuate(dateBeforeApril18) *> M.caveats.attenuate(userIsWilleke)
```

And bake a macaroon with these:

```scala
val m2: Macaroon with Authority = attenuation.runS(m1).unsafeRunSync()
// m2: Macaroon with Authority = Macaroon(
//   maybeLocation = None,
//   id = ByteVector(16 bytes, 0x18d49160dc630726098b42516284aa09),
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
//   tag = ByteVector(32 bytes, 0x82c7a4226a002e1ec75b71eba39587e9e8ebf1143840fb18d208d4a86e99b0e4)
// )
```

Use the codec to transfer it to the client:

```scala
macaroonV2.encode(m2).require.toBase64
// res0: String = "AgIQGNSRYNxjByYJi0JRYoSqCQACEWRhdGUgPCAyMDIxLTA0LTE4AAIOdXNlciA9IHdpbGxla2UAAAYggsekImoALh7HW3Hro5WH6ejr8RQ4QPsY0gjUqG6ZsOQ="
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
