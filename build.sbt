ThisBuild / organizationName := "nl.sanderdijkhuis"
ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "2.13.5"

val tsecVersion    = "0.2.1"
val refinedVersion = "0.9.21"

lazy val core = (project in file("modules/core")).settings(
  name := "macaroons-core",
  libraryDependencies ++= Seq(
    "org.typelevel"              %% "cats-tagless-macros" % "0.12",
    "io.github.jmcardon"         %% "tsec-common"         % tsecVersion,
    "io.github.jmcardon"         %% "tsec-mac"            % tsecVersion,
    "io.github.jmcardon"         %% "tsec-hash-jca"       % tsecVersion,
    "io.github.jmcardon"         %% "tsec-cipher-bouncy"  % tsecVersion,
    "eu.timepit"                 %% "refined"             % refinedVersion,
    "eu.timepit"                 %% "refined-cats"        % refinedVersion,
    "eu.timepit"                 %% "refined-scodec"      % refinedVersion,
    "eu.timepit"                 %% "refined-shapeless"   % refinedVersion,
    "io.estatico"                %% "newtype"             % "0.4.4",
    "org.scodec"                 %% "scodec-bits"         % "1.1.24",
    "org.scodec"                 %% "scodec-core"         % "1.11.7",
    "com.github.julien-truffaut" %% "monocle-core"        % "3.0.0-M4",
    "com.github.julien-truffaut" %% "monocle-macro"       % "3.0.0-M4",
    "org.scalameta"              %% "munit"               % "0.7.23" % Test
  ),
  addCompilerPlugin(
    ("org.typelevel" % "kind-projector" % "0.11.3").cross(CrossVersion.full)),
  addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1"),
  testFrameworks += new TestFramework("weaver.framework.CatsEffect"),
  scalacOptions ++= Seq(
    "-Ymacro-annotations",
    "-Xsource:3",
    "-Werror",
    "-Wunused:privates",
    "-feature",
    "-deprecation")
)

lazy val docs = project.in(file("macaroons-docs")).dependsOn(core)
  .enablePlugins(MdocPlugin)
  .settings(mdocIn := file("README.template.md"), mdocOut := file("README.md"))
