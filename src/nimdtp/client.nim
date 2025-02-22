import std/[asyncfutures, asyncdispatch, asyncnet]
import ./crypto

type
  Client*[S, R] = ref object
    isConnected: bool
    sock: AsyncSocket
    key: array[aesKeySize, byte]

proc newClient*[S, R](): Client[S, R] =
  discard # TODO

proc connect*[S, R](client: Client[S, R], host: string, port: uint16) {.async.} =
  discard # TODO

proc disconnect*[S, R](client: Client[S, R]) =
  discard # TODO

proc send*[S, R](client: Client[S, R], data: S) {.async.} =
  discard # TODO

proc connected*[S, R](client: Client[S, R]): bool =
  discard # TODO

proc getAddr*[S, R](client: Client[S, R]): (string, uint16) =
  discard # TODO

proc getServerAddr*[S, R](client: Client[S, R]): (string, uint16) =
  discard # TODO

proc handle[S, R](client: Client[S, R]) {.async.} =
  discard # TODO

proc exchangeKeys[S, R](client: Client[S, R]) {.async.} =
  discard # TODO
