import unittest
import nimdtp/[client, server, util]

proc `*`[N: SomeInteger](num: N): uint =
  uint(num)

proc `*`[I](bytes: array[I, int]): string =
  for value in bytes:
    result.add($char(value))

test "serialize and deserialize":
  type
    Foo = object
      id: int
      bar: string

  let value = Foo(id: 1, bar: "baz")
  let valueSerialized = serialize(value)
  doAssert valueSerialized == """{"id": 1, "bar": "baz"}"""
  let valueDeserialized = deserialize[Foo](valueSerialized)
  doAssert valueDeserialized == value

test "encode message size":
  doAssert encodeMessageSize(*0) == *[0, 0, 0, 0, 0]
  doAssert encodeMessageSize(*1) == *[0, 0, 0, 0, 1]
  doAssert encodeMessageSize(*255) == *[0, 0, 0, 0, 255]
  doAssert encodeMessageSize(*256) == *[0, 0, 0, 1, 0]
  doAssert encodeMessageSize(*257) == *[0, 0, 0, 1, 1]
  doAssert encodeMessageSize(*4311810305) == *[1, 1, 1, 1, 1]
  doAssert encodeMessageSize(*4328719365) == *[1, 2, 3, 4, 5]
  doAssert encodeMessageSize(*47362409218) == *[11, 7, 5, 3, 2]
  doAssert encodeMessageSize(*1099511627775) == *[255, 255, 255, 255, 255]

test "decode message size":
  doAssert decodeMessageSize(*[0, 0, 0, 0, 0]) == *0
  doAssert decodeMessageSize(*[0, 0, 0, 0, 1]) == *1
  doAssert decodeMessageSize(*[0, 0, 0, 0, 255]) == *255
  doAssert decodeMessageSize(*[0, 0, 0, 1, 0]) == *256
  doAssert decodeMessageSize(*[0, 0, 0, 1, 1]) == *257
  doAssert decodeMessageSize(*[1, 1, 1, 1, 1]) == *4311810305
  doAssert decodeMessageSize(*[1, 2, 3, 4, 5]) == *4328719365
  doAssert decodeMessageSize(*[11, 7, 5, 3, 2]) == *47362409218
  doAssert decodeMessageSize(*[255, 255, 255, 255, 255]) == *1099511627775

test "crypto":
  discard # TODO

test "server serving":
  discard # TODO

test "addresses":
  discard # TODO

test "send":
  discard # TODO

test "large send":
  discard # TODO

test "sending numerous messages":
  discard # TODO

test "sending custom types":
  discard # TODO

test "multiple clients":
  discard # TODO

test "remove client":
  discard # TODO

test "stop server while client connected":
  discard # TODO
