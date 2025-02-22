import std/[asyncfutures, asyncdispatch, asyncnet, tables]
import ./crypto

type
  ClientRepr = object
    conn: AsyncSocket
    key: array[aesKeySize, byte]

  Server*[S, R] = ref object
    isServing: bool
    sock: AsyncSocket
    clients: Table[uint, ClientRepr]
    nextClientId: uint

proc newServer*[S, R](): Server[S, R] =
  discard # TODO

proc start*[S, R](server: Server[S, R], host: string, port: uint16) {.async.} =
  discard # TODO

proc stop*[S, R](server: Server[S, R]) =
  discard # TODO

proc send*[S, R](server: Server[S, R], clientId: uint, data: S) {.async.} =
  discard # TODO

proc send*[S, R](server: Server[S, R], clientIds: openArray[uint], data: S) {.async.} =
  discard # TODO

proc sendAll*[S, R](server: Server[S, R], data: S) {.async.} =
  discard # TODO

proc serving*[S, R](server: Server[S, R]): bool =
  discard # TODO

proc getAddr*[S, R](server: Server[S, R]): (string, uint16) =
  discard # TODO

proc getClientAddr*[S, R](server: Server[S, R], clientId: uint): (string, uint16) =
  discard # TODO

proc removeClient*[S, R](server: Server[S, R], clientId: uint) =
  discard # TODO

proc serve[S, R](server: Server[S, R]) {.async.} =
  discard # TODO

proc serveClient[S, R](server: Server[S, R], clientId: uint) {.async.} =
  discard # TODO

proc newClientId[S, R](server: Server[S, R]): uint =
  discard # TODO

proc exchangeKeys[S, R](server: Server[S, R], clientId: uint, client: AsyncSocket) {.async.} =
  discard # TODO
