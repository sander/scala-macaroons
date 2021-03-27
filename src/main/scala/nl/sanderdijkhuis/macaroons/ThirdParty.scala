package nl.sanderdijkhuis.macaroons

trait ThirdParty[F[_]] {
  def prepare(rootKey: RootKey, identifier: Identifier): F[Identifier]
}
