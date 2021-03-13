package nl.sanderdijkhuis.macaroons

import nl.sanderdijkhuis.macaroons.Macaroon.Unbound

trait Marshalling[C] {
  def marshall(macaroon: Macaroon[C]): C
  def marshall(bound: Unbound[C]): C
  def unmarshallMacaroon(value: C): Option[Macaroon[C]]
  def unmarshallBound(value: C): Option[Unbound[C]]
}
