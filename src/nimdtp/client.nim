import std/[asyncdispatch, asyncfutures, asyncnet]
import ./[crypto, util]

type
  ClientOnReceive[S, R] = proc (client: Client[S, R], data: R) {.closure.}
    ## A procedure handling data received from the server.
  ClientOnDisconnected[S, R] = proc (client: Client[S, R]) {.closure.}
    ## A procedure handling the case where the client is disconnected from the
    ## server.

  ClientObj[S, R] = object ## A network client object.
    isConnected: bool
    sock: AsyncSocket
    key: AesKey
    onReceive: ClientOnReceive[S, R]
    onDisconnected: ClientOnDisconnected[S, R]

  Client*[S, R] = ref ClientObj[S, R] ## A network client.

proc exchangeKeys[S, R](client: Client[S, R]): Future[AesKey] {.warning[BareExcept]: off, async.} =
  ## Performs a cryptographic key exchange with the server.
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

proc handle[S, R](client: Client[S, R]) {.warning[BareExcept]: off, async.} =
  ## Client event loop.
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
  ## Constructs a new network client.
  new(result)
  result.isConnected = false
  result.onReceive = onReceive
  result.onDisconnected = onDisconnected

proc connect*[S, R](client: Client[S, R], host: string, port: uint16) {.warning[BareExcept]: off, async.} =
  ## Connects to a server.
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
  ## Disconnects from the server.
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  client.isConnected = false
  client.sock.close()

proc send*[S, R](client: Client[S, R], data: S) {.warning[BareExcept]: off, async.} =
  ## Sends data to the server.
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  let dataSerialized = serialize(data)
  let dataEncrypted = aesEncryptSync(client.key, dataSerialized)
  let size = encodeMessageSize(dataEncrypted.len)
  let buffer = size & dataEncrypted
  await client.sock.send(buffer)

proc connected*[S, R](client: Client[S, R]): bool {.inline.} =
  ## Is the client currently connected to a server?
  client.isConnected

proc getAddr*[S, R](client: Client[S, R]): (string, uint16) =
  ## Returns the client's address.
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  let address = client.sock.getLocalAddr()
  (address[0], address[1].uint16)

proc getServerAddr*[S, R](client: Client[S, R]): (string, uint16) =
  ## Returns the server's address.
  if not client.isConnected:
    raise newException(DTPError, "client is not connected to a server")
  let address = client.sock.getPeerAddr()
  (address[0], address[1].uint16)

proc `=destroy`*[S, R](client: ClientObj[S, R]) =
  ## Attempts to close the connection to the server if still connected when the
  ## client object is dropped.
  if client.sock != nil and not client.sock.isClosed:
    try:
      {.warning[Effect]: off.}:
        client.sock.close()
    except CatchableError, Defect:
      discard
