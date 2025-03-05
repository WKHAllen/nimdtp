import std/[asyncdispatch, asyncfutures, asyncnet, sequtils, tables]
import ./[crypto, util]

type
  ServerOnReceive[S, R] = proc (server: Server[S, R], clientId: int, data: R) {.closure.}
    ## A procedure handling data received from a client.
  ServerOnConnect[S, R] = proc (server: Server[S, R], clientId: int) {.closure.}
    ## A procedure which runs each time a new client connects.
  ServerOnDisconnect[S, R] = proc (server: Server[S, R], clientId: int) {.closure.}
    ## A procedure which runs each time a client disconnects.

  ClientRepr = object ## A representation of a connected client.
    conn: AsyncSocket
    key: AesKey

  ServerObj[S, R] = object ## A network server object.
    isServing: bool
    sock: AsyncSocket
    clients: Table[int, ClientRepr]
    nextClientId: int
    onReceive: ServerOnReceive[S, R]
    onConnect: ServerOnConnect[S, R]
    onDisconnect: ServerOnDisconnect[S, R]

  Server*[S, R] = ref ServerObj[S, R] ## A network server.

proc exchangeKeys[S, R](server: Server[S, R], clientId: int, conn: AsyncSocket): Future[AesKey] {.warning[BareExcept]: off, async.} =
  ## Performs a cryptographic key exchange with a connecting client.
  let (publicKey, privateKey) = newRsaKeyPairSync()
  let publicKeyStr = $publicKey
  let publicKeySize = encodeMessageSize(publicKeyStr.len)
  let publicKeyBuffer = publicKeySize & publicKeyStr
  await conn.send(publicKeyBuffer)
  let size = await conn.recv(lenSize)
  let keySize = decodeMessageSize(size)
  let keyBuffer = await conn.recv(keySize)
  let decryptedKeyBuffer = rsaDecryptSync(privateKey, keyBuffer)
  result = decryptedKeyBuffer.toAesKey

proc newClientId[S, R](server: Server[S, R]): int =
  ## Returns the next available client ID.
  result = server.nextClientId
  inc server.nextClientId

proc serveClient[S, R](server: Server[S, R], clientId: int) {.warning[BareExcept]: off, async.} =
  ## Event loop for a single connected client.
  if server.onConnect != nil:
    server.onConnect(server, clientId)
  defer:
    if server.onDisconnect != nil:
      server.onDisconnect(server, clientId)
  let client = server.clients[clientId]
  try:
    while server.isServing:
      let size = await client.conn.recv(lenSize)
      if size.len != lenSize:
        break
      let msgSize = decodeMessageSize(size)
      let buffer = await client.conn.recv(msgSize)
      if buffer.len != msgSize:
        break
      let bufferDecrypted = aesDecryptSync(client.key, buffer)
      let data = deserialize[R](bufferDecrypted)
      if server.onReceive != nil:
        server.onReceive(server, clientId, data)
  except CatchableError:
    if server.isServing and server.clients.hasKey(clientId):
      server.removeClient(clientId)

proc serve[S, R](server: Server[S, R]) {.warning[BareExcept]: off, async.} =
  ## Event loop for the server listener.
  while server.isServing:
    try:
      let conn = await server.sock.accept()
      let clientId = server.newClientId()
      let key = await server.exchangeKeys(clientId, conn)
      server.clients[clientId] = ClientRepr(conn: conn, key: key)
      asyncCheck server.serveClient(clientId)
    except CatchableError:
      discard # this handles the case where an error is thrown because the server has been stopped, and ignores all other errors

proc newServer*[S, R](onReceive: ServerOnReceive[S, R] = nil, onConnect: ServerOnConnect[S, R] = nil, onDisconnect: ServerOnDisconnect[S, R] = nil): Server[S, R] =
  ## Constructs a new network server.
  new(result)
  result.isServing = false
  result.clients = initTable[int, ClientRepr]()
  result.nextClientId = 0
  result.onReceive = onReceive
  result.onConnect = onConnect
  result.onDisconnect = onDisconnect

proc start*[S, R](server: Server[S, R], host: string, port: uint16) {.warning[BareExcept]: off, async.} =
  ## Starts the server listening on the given host and port.
  if server.isServing:
    raise newException(DTPError, "server is already serving")
  let sock = newAsyncSocket()
  sock.setSockOpt(OptReuseAddr, true)
  sock.setSockOpt(OptReusePort, true)
  sock.bindAddr(Port(port), host)
  sock.listen()
  server.sock = sock
  server.isServing = true
  asyncCheck server.serve()

proc stop*[S, R](server: Server[S, R]) =
  ## Stops the server, disconnecting all clients in the process.
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  server.isServing = false
  for client in server.clients.values:
    client.conn.close()
  server.sock.close()

proc send*[S, R](server: Server[S, R], clientIds: seq[int], data: S) {.warning[BareExcept]: off, async.} =
  ## Sends data to a list of clients.
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let dataSerialized = serialize(data)
  for clientId in clientIds:
    let client = server.clients[clientId]
    let dataEncrypted = aesEncryptSync(client.key, dataSerialized)
    let size = encodeMessageSize(dataEncrypted.len)
    let buffer = size & dataEncrypted
    await client.conn.send(buffer)

proc send*[S, R](server: Server[S, R], clientId: int, data: S) {.warning[BareExcept]: off, async.} =
  ## Sends data to a single client.
  await server.send(@[clientId], data)

proc sendAll*[S, R](server: Server[S, R], data: S) {.warning[BareExcept]: off, async.} =
  ## Sends data to all connected clients.
  await server.send(toSeq(server.clients.keys), data)

proc serving*[S, R](server: Server[S, R]): bool {.inline.} =
  ## Is the server currently serving?
  server.isServing

proc getAddr*[S, R](server: Server[S, R]): (string, uint16) =
  ## Returns the server's address.
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let address = server.sock.getLocalAddr()
  (address[0], address[1].uint16)

proc getClientAddr*[S, R](server: Server[S, R], clientId: int): (string, uint16) =
  ## Returns a client's address.
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let address = server.clients[clientId].conn.getPeerAddr()
  (address[0], address[1].uint16)

proc removeClient*[S, R](server: Server[S, R], clientId: int) =
  ## Disconnects a client from the server.
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let client = server.clients[clientId]
  client.conn.close()
  server.clients.del(clientId)

proc `=destroy`*[S, R](server: ServerObj[S, R]) =
  ## Attempts to shut down the server and disconnect all clients if still
  ## serving when the server object is dropped.
  for client in server.clients.values:
    if client.conn != nil and not client.conn.isClosed:
      try:
        {.warning[Effect]: off.}:
          client.conn.close()
      except CatchableError, Defect:
        discard
  if server.sock != nil and not server.sock.isClosed:
    try:
      {.warning[Effect]: off.}:
        server.sock.close()
    except CatchableError, Defect:
      discard
