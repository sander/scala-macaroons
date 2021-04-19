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

Specify a strategy to generate macaroon and caveat identifiers unique at this photo service:

```scala mdoc:silent
import cats.effect._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import nl.sanderdijkhuis.macaroons.effects._

val identifiers: Identifiers[IO] = Identifiers.secureRandom
```

Then specify a strategy to store root keys, to generate and verify macaroons:

```scala mdoc:silent
import nl.sanderdijkhuis.macaroons.repositories._
import tsec.mac.jca._

val rootKeyRepository
    : KeyRepository[IO, Identifier, MacSigningKey[HMACSHA256]] = KeyRepository
  .inMemoryRef[IO, MacSigningKey[HMACSHA256]].unsafeRunSync()
```

Now make the principal modules to represent our photo service:

```scala mdoc:silent
import eu.timepit.refined.auto._
import nl.sanderdijkhuis.macaroons.modules._
import tsec.mac.jca._

val location: Location = Location("https://photos.example/")
val M: Macaroons[IO]   = Macaroons.make()
val A: Assertions[IO]  = Assertions.make(Some(location), M, rootKeyRepository)
```

With this principal we can create new macaroons:

```scala mdoc
val m1: Macaroon with Authority = A.service.assert().unsafeRunSync()
```

Or define some caveats:

```scala mdoc:silent
import cats.implicits._

val dateBeforeApril18: Predicate = Predicate.from("date < 2021-04-18")
val userIsWilleke: Predicate     = Predicate.from("user = willeke")

val attenuation: Transformation[IO, Unit] = M.caveats
  .attenuate(dateBeforeApril18) *> M.caveats.attenuate(userIsWilleke)
```

And bake a macaroon with these:

```scala mdoc
val m2: Macaroon with Authority = attenuation.runS(m1).unsafeRunSync()
```

Use the codec to transfer it to the client:

```scala mdoc
import nl.sanderdijkhuis.macaroons.codecs.macaroon._

println(macaroonV2.encode(m2).require.toBase64)
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
