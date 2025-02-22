const lenSize* = 5

proc encodeMessageSize*(size: uint): array[lenSize, byte] =
  var size = size # need to mutate size inside this proc but don't want to mutate the caller's variable
  for i in 0 ..< lenSize:
    result[lenSize - i - 1] = byte(size and 0xff)
    size = size shr 8

proc decodeMessageSize*(encodedSize: array[lenSize, byte]): uint =
  for i in 0 ..< lenSize:
    result = result shl 8
    result += uint(encodedSize[i])
