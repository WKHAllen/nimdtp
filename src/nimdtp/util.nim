import std/marshal

const lenSize* = 5

type
  DTPError* = object of CatchableError

proc serialize*[T](data: T): string =
  $$data

proc deserialize*[T](dataSerialized: string): T =
  to[T](dataSerialized)

proc encodeMessageSize*(size: uint): string =
  var size = size # need to mutate size inside this proc but don't want to mutate the caller's variable
  for i in 0 ..< lenSize:
    result.insert($char(size and 0xff), 0)
    size = size shr 8

proc decodeMessageSize*(encodedSize: string): uint =
  for i in 0 ..< lenSize:
    result = result shl 8
    result += uint(encodedSize[i])
