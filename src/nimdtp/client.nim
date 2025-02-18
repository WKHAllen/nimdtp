import std/asyncfutures
import std/asyncdispatch
import std/asyncnet
import ./crypto

type
  Client*[S, R] = ref object
    connected: bool
    sock: AsyncSocket
    key: array[0..aesKeySize, byte]

proc newClient*[S, R](): Client[S, R] =
  discard

proc connect*[S, R](client: Client[S, R], host: string, port: uint16) {.async.} =
  discard

proc disconnect*[S, R](client: Client[S, R]) =
  discard

proc send*[S, R](client: Client[S, R], data: S) {.async.} =
  discard

proc connected*[S, R](client: Client[S, R]): bool =
  discard

proc getAddr*[S, R](client: Client[S, R]): (string, uint16) =
  discard

proc getServerAddr*[S, R](client: Client[S, R]): (string, uint16) =
  discard

proc handle[S, R](client: Client[S, R]) {.async.} =
  discard

proc exchangeKeys[S, R](client: Client[S, R]) {.async.} =
  discard
