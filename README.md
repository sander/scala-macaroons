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

```scala
import cats.effect._
import nl.sanderdijkhuis.macaroons.domain.macaroon._

val generateIdentifier: IO[Identifier] = {
  var i = -1
  IO { i += 1; Identifier.from(i) }
}
```

Then specify a strategy to store root keys, to generate and verify macaroons:

```scala
import nl.sanderdijkhuis.macaroons.repositories._
import nl.sanderdijkhuis.macaroons.services._
import nl.sanderdijkhuis.macaroons.services.MacaroonService.RootKey

val rootKeyRepository = KeyRepository
    .inMemoryRef[IO, Identifier, RootKey](generateIdentifier)
    .unsafeRunSync()
```

The same for discharge keys, to generate discharges for third-party caveats:

```scala
val dischargeKeyRepository = KeyRepository
    .inMemoryRef[IO, Identifier, (RootKey, Predicate)](generateIdentifier)
    .unsafeRunSync()
```

Now make the principal to represent our photo service:

```scala
import eu.timepit.refined.auto._

val location = Location("https://photos.example/")
val principal = PrincipalService.make[IO](Some(location))(
    rootKeyRepository, dischargeKeyRepository)
```

With this principal we can create new macaroons:

```scala
val m1 = principal.assert().unsafeRunSync()
// m1: Macaroon with Authority = Macaroon(
//   maybeLocation = Some(value = https://photos.example/),
//   id = ByteVector(1 bytes, 0x30),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x57ce26058b253d83d3d821dd3c81b41082270950c52db56dac16084e1334b713)
// )
```

Or macaroons with caveats:

```scala
val m2 = (
  for {
    m <- principal.assert()
    m <- principal.addFirstPartyCaveat(m, Identifier.from("date < 2021-04-18"))
    m <- principal.addFirstPartyCaveat(m, Identifier.from("user = willeke"))
  } yield m
).unsafeRunSync()
// m2: Macaroon with Authority = Macaroon(
//   maybeLocation = Some(value = https://photos.example/),
//   id = ByteVector(1 bytes, 0x31),
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
//   tag = ByteVector(32 bytes, 0xe8e71edc61be65a51a13018c9b854124a824448a71e6074725bc10bdc81ce149)
// )
```

Use the codec to transfer it to the client:

```scala
import nl.sanderdijkhuis.macaroons.codecs.macaroon._

macaroonV2.encode(m2).require.toBase64
// res0: String = "AgEXaHR0cHM6Ly9waG90b3MuZXhhbXBsZS8CATEAAhFkYXRlIDwgMjAyMS0wNC0xOAACDnVzZXIgPSB3aWxsZWtlAAAGIOjnHtxhvmWlGhMBjJuFQSSoJESKceYHRyW8EL3IHOFJ"
```

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
