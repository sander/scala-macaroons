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

Specify a strategy to generate macaroon and caveat identifiers unique at this photo service. In practice you could use something like `SecureRandomId.Interactive` from [TSec](https://jmcardon.github.io/tsec/), but for now we will keep a global counter:

```scala mdoc:silent
import cats.effect._
import cats.effect.concurrent._
import eu.timepit.refined.refineV
import eu.timepit.refined.collection._
import nl.sanderdijkhuis.macaroons.domain.macaroon._
import tsec.common._
import scodec.bits._

val generateIdentifier: IO[Identifier] = Ref.of[IO, Int](0)
    .unsafeRunSync()
    .modify(i => (i + 1, Identifier.from(
        refineV[NonEmpty].unsafeFrom(s"$i"))))
```

Then specify a strategy to store root keys, to generate and verify macaroons:

```scala mdoc:silent
import nl.sanderdijkhuis.macaroons.repositories._
import nl.sanderdijkhuis.macaroons.services._
import nl.sanderdijkhuis.macaroons.services.MacaroonService.RootKey

val rootKeyRepository = KeyRepository
    .inMemoryRef[IO, Identifier, RootKey](generateIdentifier)
    .unsafeRunSync()
```

The same for discharge keys, to generate discharges for third-party caveats:

```scala mdoc:silent
val dischargeKeyRepository = KeyRepository
    .inMemoryRef[IO, Identifier, (RootKey, Predicate)](generateIdentifier)
    .unsafeRunSync()
```

Now make the principal to represent our photo service:

```scala mdoc:silent
import eu.timepit.refined.auto._

val location = Location("https://photos.example/")
val principal = PrincipalService.make[IO](Some(location))(
    rootKeyRepository, dischargeKeyRepository)
```

With this principal we can create new macaroons:

```scala mdoc
val m1 = principal.assert().unsafeRunSync()
```

Or macaroons with caveats:

```scala mdoc
val m2 = (
  for {
    m <- principal.assert()
    m <- principal.addFirstPartyCaveat(m, Identifier.from("date < 2021-04-18"))
    m <- principal.addFirstPartyCaveat(m, Identifier.from("user = willeke"))
  } yield m
).unsafeRunSync()
```

Use the codec to transfer it to the client:

```scala mdoc
import nl.sanderdijkhuis.macaroons.codecs.macaroon._

macaroonV2.encode(m2).require.toBase64
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
