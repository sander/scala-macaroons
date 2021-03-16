package nl.sanderdijkhuis.macaroons

trait KeyRepository[F[_]] {

  def protectRootKey(rootKey: RootKey): F[Identifier]

  def protectRootKeyAndPredicate(rootKey: RootKey,
                                 identifier: Identifier): F[Identifier]

  def restoreRootKey(identifier: Identifier): F[RootKey]

  def restoreRootKeyAndPredicate(
      identifier: Identifier): F[(RootKey, Predicate)]

}

object KeyRepository {

  def apply[F[_]](implicit repository: KeyRepository[F]): KeyRepository[F] =
    repository
}
