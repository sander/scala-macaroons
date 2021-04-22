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
//   id = ByteVector(16 bytes, 0x0b9ddf03534a05975a6520aab2523ac2),
//   caveats = Vector(),
//   tag = ByteVector(32 bytes, 0x2906520c8a6c9210af345b2a8081a0a7e641bf4fb37747ddee26475dabfee136)
// )
```

We can serialize it to transfer it to the client:

```scala
macaroonV2.encode(macaroon).require.toBase64
// res0: String = "AgIQC53fA1NKBZdaZSCqslI6wgAABiApBlIMimySEK80WyqAgaCn5kG/T7N3R93uJkddq/7hNg=="
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
//   id = ByteVector(16 bytes, 0x0b9ddf03534a05975a6520aab2523ac2),
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
//   tag = ByteVector(32 bytes, 0x33278239bb69e62f08d6c42dd6b4115801f186d48178c10c850fcaebf2e5a07f)
// )
```

Whenever a user makes a request with this macaroon, we can authorize the request by verifying the macaroon to a set of true predicates:

```scala
val someOtherPredicate = Predicate.from("ip = 192.168.0.1")
val predicatesForThisRequest =
  Set(dateBeforeApril18, userIsWilleke, someOtherPredicate)
```

Note that although this particular example uses a set, we could have used any function `Predicate => Boolean`. One particularly useful type of function matches the prefix of the predicate (e.g. `date < `), parses the rest of the predicate and verifies this with data from the request context. 

To verify the macaroon, again:

```scala
assertions.service.verify(macaroon2, predicatesForThisRequest).unsafeRunSync()
// res2: Boolean = true
```

### Adding third-party caveats

Although we could have a verifier function query some external service as a side effect, macaroons offer a better way. On our photo service, we could confine a macaroon to be used only within a certain context, asserted by for example an authentication service. The confinement is again expressed as a caveat, containing a challenge to be resolved at the authentication service. This is proven using a *discharge macaroon* issued by the authentication service, which could in itself contain caveats.

To demonstrate this, first we will create a stub authentication service:

TODO

## Maintenance

To compile README.md: `sbt "docs/mdoc"`
