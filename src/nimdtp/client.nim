import std/[asyncdispatch, asyncfutures, asyncnet]
import ./[crypto, util]

type
  ClientOnReceive[S, R] = proc (client: Client[S, R], data: R) {.closure.}
  ClientOnDisconnected[S, R] = proc (client: Client[S, R]) {.closure.}

  ClientObj[S, R] = object
    isConnected: bool
    sock: AsyncSocket
    key: array[aesKeySize, byte]
    onReceive: ClientOnReceive[S, R]
    onDisconnected: ClientOnDisconnected[S, R]

  Client*[S, R] = ref ClientObj[S, R]

proc exchangeKeys[S, R](client: Client[S, R]): Future[array[aesKeySize, byte]] {.async.} =
  discard # TODO

proc handle[S, R](client: Client[S, R]) {.async.} =
  try:
    while client.isConnected:
      let size = await client.sock.recv(lenSize)
      if size.len != lenSize:
        break
      let msgSize = decodeMessageSize(size)
      let buffer = await client.sock.recv(int(msgSize))
      if buffer.len != int(msgSize):
        break
      # TODO: decrypt data
      let data = deserialize[R](buffer)
      if client.onReceive != nil:
        client.onReceive(client, data)
  except CatchableError:
    discard
  finally:
    if client.isConnected:
      client.isConnected = false
      client.sock.close()
      if client.onDisconnected != nil:
        client.onDisconnected(client)

proc newClient*[S, R](onReceive: ClientOnReceive[S, R] = nil, onDisconnected: ClientOnDisconnected[S, R] = nil): Client[S, R] =
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
  await sock.connect(host, Port(port))
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
  let address = client.sock.getLocalAddr()
  (address[0], address[1].uint16)

proc getServerAddr*[S, R](client: Client[S, R]): (string, uint16) =
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  let address = client.sock.getPeerAddr()
  (address[0], address[1].uint16)

proc `=destroy`*[S, R](client: ClientObj[S, R]) =
  client.sock.close()
