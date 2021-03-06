name := "macaroons"
version := "0.1.0-SNAPSHOT"
scalaVersion := "2.13.5"

libraryDependencies ++= Seq(
  "com.github.nitram509" % "jmacaroons" % "0.4.1",
  "org.typelevel" %% "cats-effect" % "2.3.1",
  "io.github.jmcardon" %% "tsec-common" % "0.2.1",
  "io.github.jmcardon" %% "tsec-mac" % "0.2.1",
  "com.google.crypto.tink" % "tink" % "1.5.0",
  "io.github.jmcardon" %% "tsec-cipher-bouncy" % "0.2.1",
  "org.typelevel" %% "log4cats-slf4j" % "1.2.0",
  "org.slf4j" % "slf4j-simple" % "1.7.30",
  "co.fs2" %% "fs2-core" % "2.5.0",
  "io.estatico" %% "newtype" % "0.4.4",
  "com.disneystreaming" %% "weaver-cats" % "0.6.0-M6" % Test
)

testFrameworks += new TestFramework("weaver.framework.CatsEffect")

scalacOptions += "-Ymacro-annotations"
