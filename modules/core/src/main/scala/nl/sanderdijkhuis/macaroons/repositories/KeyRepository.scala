package nl.sanderdijkhuis.macaroons.repositories

import cats.data._
import cats.implicits._
import cats.tagless._
import cats._
import monocle.Lens

@finalAlg
@autoFunctorK
trait KeyRepository[F[_], Identifier, Key] {

  def protect(key: Key): F[Identifier]

  def recover(identifier: Identifier): F[Option[Key]]
}

object KeyRepository {

  private class InMemory[S, I, K](val lens: Lens[S, Map[I, K]],
                                  val id: State[S, I])
      extends KeyRepository[State[S, *], I, K] {

    def protect(key: K): State[S, I] = id.transform {
      case (s, id) => (lens.modify(m => m + (id -> key))(s), id)
    }

    def recover(identifier: I): State[S, Option[K]] =
      State(s => (s, lens.get(s).get(identifier)))
  }

  def inMemory[S, I, K](lens: Lens[S, Map[I, K]],
                        id: State[S, I]): KeyRepository[State[S, *], I, K] =
    new InMemory(lens, id)

  private def functorK[F[_]: Applicative, S]: State[S, *] ~> StateT[F, S, *] =
    λ[State[S, *] ~> StateT[F, S, *]](s => StateT(t => s.run(t).value.pure[F]))

  def inMemoryF[F[_]: Applicative, S, I, K](
      lens: Lens[S, Map[I, K]],
      id: State[S, I]): KeyRepository[StateT[F, S, *], I, K] =
    mapK(new InMemory(lens, id))(functorK[F, S])
}
