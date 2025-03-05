import std/marshal

const lenSize* = 5

type
  DTPError* = object of CatchableError
    ## General type encompassing Data Transfer Protocol errors.

proc serialize*[T](data: T): string =
  ## Serializes a value of type `T` to a string.
  $$data

proc deserialize*[T](dataSerialized: string): T =
  ## Deserializes a string into a new value of type `T`.
  to[T](dataSerialized)

proc encodeMessageSize*(size: int): string =
  ## Encodes the size portion of a message.
  var size = size # need to mutate size inside this proc but don't want to mutate the caller's variable
  for i in 0 ..< lenSize:
    result.insert($char(size and 0xff), 0)
    size = size shr 8

proc decodeMessageSize*(encodedSize: string): int =
  ## Decodes the size portion of a message.
  for i in 0 ..< lenSize:
    result = result shl 8
    result += int(encodedSize[i])
