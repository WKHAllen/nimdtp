import std/[asyncdispatch, asyncfutures, asyncnet]
import ./[crypto, util]

type
  ClientOnReceive[S, R] = proc (client: Client[S, R], data: R) {.closure.}
  ClientOnDisconnected[S, R] = proc (client: Client[S, R]) {.closure.}

  ClientObj[S, R] = object
    isConnected: bool
    sock: AsyncSocket
    key: AesKey
    onReceive: ClientOnReceive[S, R]
    onDisconnected: ClientOnDisconnected[S, R]

  Client*[S, R] = ref ClientObj[S, R]

proc exchangeKeys[S, R](client: Client[S, R]): Future[AesKey] {.async.} =
  let size = await client.sock.recv(lenSize)
  let publicKeySize = decodeMessageSize(size)
  let publicKeyBuffer = await client.sock.recv(publicKeySize)
  let publicKey = publicKeyBuffer.toRsaPublicKey
  let key = newAesKeySync()
  let keyStr = $key
  let encryptedKey = rsaEncryptSync(publicKey, keyStr)
  let encryptedKeySize = encodeMessageSize(encryptedKey.len)
  let encryptedKeyBuffer = encryptedKeySize & encryptedKey
  await client.sock.send(encryptedKeyBuffer)
  result = key

proc handle[S, R](client: Client[S, R]) {.async.} =
  try:
    while client.isConnected:
      let size = await client.sock.recv(lenSize)
      if size.len != lenSize:
        break
      let msgSize = decodeMessageSize(size)
      let buffer = await client.sock.recv(msgSize)
      if buffer.len != msgSize:
        break
      let bufferDecrypted = aesDecryptSync(client.key, buffer)
      let data = deserialize[R](bufferDecrypted)
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
  let dataEncrypted = aesEncryptSync(client.key, dataSerialized)
  let size = encodeMessageSize(dataEncrypted.len)
  let buffer = size & dataEncrypted
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
  if client.sock != nil and not client.sock.isClosed:
    try:
      client.sock.close()
    except CatchableError, Defect:
      discard
