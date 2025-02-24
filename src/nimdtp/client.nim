import std/[asyncdispatch, asyncfutures, asyncnet]
import ./[crypto, util]

type
  ClientOnReceive[R] = proc (data: R) {.closure.}
  ClientOnDisconnected = proc () {.closure.}

  ClientObj[S, R] = object
    isConnected: bool
    sock: AsyncSocket
    key: array[aesKeySize, byte]
    onReceive: ClientOnReceive[R]
    onDisconnected: ClientOnDisconnected

  Client*[S, R] = ref ClientObj[S, R]

proc newClient*[S, R](onReceive: ClientOnReceive[R] = nil, onDisconnected: ClientOnDisconnected = nil): Client[S, R] =
  new(result)
  result.isConnected = false
  result.onReceive = onReceive
  result.onDisconnected = onDisconnected

proc connect*[S, R](client: Client[S, R], host: string, port: uint16) {.async.} =
  if client.isConnected:
    raise newException(DTPError, "client is already connected to a server")
  let sock = newAsyncSocket()
  sock.setSockOpt(OptReuseAddr, true)
  sock.setSockOpt(OptReusePort, true)
  await sock.connect(host, port)
  client.sock = sock
  client.isConnected = true
  client.key = await client.exchangeKeys()
  asyncCheck client.handle()

proc disconnect*[S, R](client: Client[S, R]) =
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  client.isConnected = false
  client.sock.close()

proc send*[S, R](client: Client[S, R], data: S) {.async.} =
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  let dataSerialized = serialize(data)
  # TODO: encrypt data
  let size = encodeMessageSize(dataSerialized.len)
  let buffer = size & dataSerialized
  await client.sock.send(buffer)

proc connected*[S, R](client: Client[S, R]): bool {.inline.} =
  client.isConnected

proc getAddr*[S, R](client: Client[S, R]): (string, uint16) =
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  client.sock.getLocalAddr

proc getServerAddr*[S, R](client: Client[S, R]): (string, uint16) =
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  client.sock.getPeerAddr

proc handle[S, R](client: Client[S, R]) {.async.} =
  try:
    while client.isConnected:
      let size = await client.sock.recv(lenSize)
      let msgSize = decodeMessageSize(size)
      let buffer = await client.sock.recv(msgSize)
      # TODO: decrypt data
      let data = deserialize[R](buffer)
      client.onReceive(data)
  except CatchableError:
    discard
  finally:
    if client.isConnected:
      client.isConnected = false
      client.sock.close()
      client.onDisconnected()

proc exchangeKeys[S, R](client: Client[S, R]): Future[array[aesKeySize, byte]] {.async.} =
  discard # TODO

proc `=destroy`*[S, R](client: ClientObj[S, R]) =
  client.disconnect()
