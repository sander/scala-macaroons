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

```scala mdoc
import cats.effect._
import cats.implicits._
import eu.timepit.refined.auto._
```

Import macaroons dependencies:

```scala mdoc
import nl.sanderdijkhuis.macaroons.codecs.macaroon._
import nl.sanderdijkhuis.macaroons.effects._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.modules._
import nl.sanderdijkhuis.macaroons.repositories._
```

Specify a strategy to generate macaroon and caveat identifiers unique at this photo service:

```scala mdoc:silent
val identifiers: Identifiers[IO] = Identifiers.secureRandom
```

Then specify a strategy to store root keys, to generate and verify macaroons:

```scala mdoc:silent
val rootKeys: RootKeys[IO] = RootKeys.makeInMemory().unsafeRunSync()
```

Now make the principal module to represent our photo service:

```scala mdoc:silent
val assertions: Assertions[IO] = Assertions.make(rootKeys.repository)
```

With this principal we can create new macaroons:

```scala mdoc
val m1: Macaroon with Authority = assertions.service.assert().unsafeRunSync()
```

Or define some caveats:

```scala mdoc:silent
val dateBeforeApril18: Predicate = Predicate.from("date < 2021-04-18")
val userIsWilleke: Predicate     = Predicate.from("user = willeke")

val M: Macaroons[IO] = assertions.macaroons
val attenuation: Transformation[IO, Unit] =
  M.caveats.attenuate(dateBeforeApril18) *> M.caveats.attenuate(userIsWilleke)
```

And bake a macaroon with these:

```scala mdoc
val m2: Macaroon with Authority = attenuation.runS(m1).unsafeRunSync()
```

Use the codec to transfer it to the client:

```scala mdoc
macaroonV2.encode(m2).require.toBase64
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
