import std/[asyncfutures, asyncdispatch, asyncnet, tables]
import ./crypto

type
  ServerOnReceive[R] = proc (clientId: uint, data: R) {.closure.}
  ServerOnConnect = proc (clientId: uint) {.closure.}
  ServerOnDisconnect = proc (clientId: uint) {.closure.}

  ClientRepr = object
    conn: AsyncSocket
    key: array[aesKeySize, byte]

  ServerObj[S, R] = object
    isServing: bool
    sock: AsyncSocket
    clients: Table[uint, ClientRepr]
    nextClientId: uint

  ServerRef*[S, R] = ref ServerObj[S, R]

proc newServer*[S, R](): ServerRef[S, R] =
  discard # TODO

proc start*[S, R](server: ServerRef[S, R], host: string, port: uint16) {.async.} =
  discard # TODO

proc stop*[S, R](server: ServerRef[S, R]) =
  discard # TODO

proc send*[S, R](server: ServerRef[S, R], clientId: uint, data: S) {.async.} =
  discard # TODO

proc send*[S, R](server: ServerRef[S, R], clientIds: openArray[uint], data: S) {.async.} =
  discard # TODO

proc sendAll*[S, R](server: ServerRef[S, R], data: S) {.async.} =
  discard # TODO

proc serving*[S, R](server: ServerRef[S, R]): bool {.inline.} =
  server.isServing

proc getAddr*[S, R](server: ServerRef[S, R]): (string, uint16) =
  discard # TODO

proc getClientAddr*[S, R](server: ServerRef[S, R], clientId: uint): (string, uint16) =
  discard # TODO

proc removeClient*[S, R](server: ServerRef[S, R], clientId: uint) =
  discard # TODO

proc serve[S, R](server: ServerRef[S, R]) {.async.} =
  discard # TODO

proc serveClient[S, R](server: ServerRef[S, R], clientId: uint) {.async.} =
  discard # TODO

proc newClientId[S, R](server: ServerRef[S, R]): uint =
  discard # TODO

proc exchangeKeys[S, R](server: ServerRef[S, R], clientId: uint, client: AsyncSocket) {.async.} =
  discard # TODO

proc `=destroy`*[S, R](server: ServerObj[S, R]) =
  server.stop()
