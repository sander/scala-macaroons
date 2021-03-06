package nl.sanderdijkhuis.macaroons

import io.estatico.newtype.macros.newtype

import scala.annotation.tailrec

/**
  * The encode and decode functions are copied from
  * [[https://github.com/fluency03/varint]] with the following license:
  *
MIT License

Copyright (c) 2018 Chang Liu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
  *
  * @see [[https://developers.google.com/protocol-buffers/docs/encoding#varints]]
  */
object Varint {
  def encode(value: Int): Array[Byte] = {
    @tailrec
    def rec(value: Int, acc: Array[Byte]): Array[Byte] =
      if ((value & 0xFFFFFF80) == 0) acc :+ (value & 0x7F).toByte
      else rec(value >>> 7, acc :+ ((value & 0x7F) | 0x80).toByte)

    rec(value, Array())
  }

  @newtype case class Offset(toInt: Int)

  def decodeToInt(bytes: Array[Byte], offset: Offset): Option[(Int, Offset)] = {
    @tailrec
    def rec(index: Int, shift: Int, acc: Int): Option[(Int, Offset)] =
      if (index >= bytes.length)
        None
      else if ((bytes(index) & 0x80) == 0)
        Some(
          (acc | (bytes(index) << shift),
           Offset(index + 1 /*- offset.toInt*/ )))
      else
        rec(index + 1, shift + 7, acc | ((bytes(index) & 0x7F) << shift))

    rec(offset.toInt, 0, 0)
  }
}
