val tsecVersion = "0.2.1"
val refinedVersion = "0.9.21"

lazy val core = (project in file("modules/core")).settings(
  name := "macaroons-core",
  organizationName := "nl.sanderdijkhuis",
  version := "0.1.0-SNAPSHOT",
  scalaVersion := "2.13.5",
  libraryDependencies ++= Seq(
    "org.typelevel" %% "cats-effect" % "2.3.1",
    "org.typelevel" %% "cats-tagless-macros" % "0.12",
    "io.github.jmcardon" %% "tsec-common" % tsecVersion,
    "io.github.jmcardon" %% "tsec-mac" % tsecVersion,
    "io.github.jmcardon" %% "tsec-hash-jca" % tsecVersion,
    "io.github.jmcardon" %% "tsec-cipher-bouncy" % tsecVersion,
    "eu.timepit" %% "refined" % refinedVersion,
    "eu.timepit" %% "refined-cats" % refinedVersion,
    "eu.timepit" %% "refined-scodec" % refinedVersion,
    "eu.timepit" %% "refined-shapeless" % refinedVersion,
    "co.fs2" %% "fs2-core" % "2.5.0",
    "io.estatico" %% "newtype" % "0.4.4",
    "org.scodec" %% "scodec-bits" % "1.1.24",
    "org.scodec" %% "scodec-core" % "1.11.7",
    "com.github.julien-truffaut" %% "monocle-core" % "3.0.0-M4",
    "com.github.julien-truffaut" %% "monocle-macro" % "3.0.0-M4",
    "com.disneystreaming" %% "weaver-cats" % "0.6.0-M6" % Test
  ),
  addCompilerPlugin(
    "org.typelevel" % "kind-projector" % "0.11.3" cross CrossVersion.full),
  addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1"),
  testFrameworks += new TestFramework("weaver.framework.CatsEffect"),
  scalacOptions ++= Seq("-Ymacro-annotations",
                        "-Xsource:3",
                        "-Werror",
                        "-Wunused:privates",
                        "-feature",
                        "-deprecation")
)
