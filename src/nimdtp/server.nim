import std/asyncfutures
import std/asyncdispatch
import std/asyncnet
import std/tables
import ./crypto

type
  ClientRepr = object
    conn: AsyncSocket
    key: array[0..aesKeySize, byte]

type
  Server*[S, R] = ref object
    serving: bool
    sock: AsyncSocket
    clients: Table[uint, ClientRepr]
    nextClientId: uint

proc newServer*[S, R](): Server[S, R] =
  discard

proc start*[S, R](server: Server[S, R], host: string, port: uint16) {.async.} =
  discard

proc stop*[S, R](server: Server[S, R]) =
  discard

proc send*[S, R](server: Server[S, R], clientId: uint, data: S) {.async.} =
  discard

proc send*[S, R](server: Server[S, R], clientIds: openArray[uint], data: S) {.async.} =
  discard

proc sendAll*[S, R](server: Server[S, R], data: S) {.async.} =
  discard

proc serving*[S, R](server: Server[S, R]): bool =
  discard

proc getAddr*[S, R](server: Server[S, R]): (string, uint16) =
  discard

proc getClientAddr*[S, R](server: Server[S, R], clientId: uint): (string, uint16) =
  discard

proc removeClient*[S, R](server: Server[S, R], clientId: uint) =
  discard

proc serve[S, R](server: Server[S, R]) {.async.} =
  discard

proc serveClient[S, R](server: Server[S, R], clientId: uint) {.async.} =
  discard

proc newClientId[S, R](server: Server[S, R]): uint =
  discard

proc exchangeKeys[S, R](server: Server[S, R], clientId: uint, client: AsyncSocket) {.async.} =
  discard
