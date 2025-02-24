import std/[asyncdispatch, asyncfutures, asyncnet, sequtils, tables]
import ./[crypto, util]

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
    onReceive: ServerOnReceive[R]
    onConnect: ServerOnConnect
    onDisconnect: ServerOnDisconnect

  Server*[S, R] = ref ServerObj[S, R]

proc newServer*[S, R](onReceive: ServerOnReceive[R] = nil, onConnect: ServerOnConnect = nil, onDisconnect: ServerOnDisconnect = nil): Server[S, R] =
  new(result)
  result.isServing = false
  result.clients = initTable[uint, ClientRepr]()
  result.nextClientId = 0
  result.onReceive = onReceive
  result.onConnect = onConnect
  result.onDisconnect = onDisconnect

proc start*[S, R](server: Server[S, R], host: string, port: uint16) {.async.} =
  if server.isServing:
    raise newException(DTPError, "server is already serving")
  let sock = newAsyncSocket()
  sock.setSockOpt(OptReuseAddr, true)
  sock.setSockOpt(OptReusePort, true)
  sock.bindAddr(port, host)
  sock.listen()
  server.sock = sock
  server.isServing = true
  asyncCheck server.serve()

proc stop*[S, R](server: Server[S, R]) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  server.isServing = false
  for client in server.clients.values:
    client.conn.close()
  server.sock.close()

proc send*[S, R](server: Server[S, R], clientId: uint, data: S) {.async.} =
  await server.send([clientId], data)

proc send*[S, R](server: Server[S, R], clientIds: openArray[uint], data: S) {.async.} =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let dataSerialized = serialize(data)
  for clientId in clientIds:
    let client = server.clients[clientId]
    # TODO: encrypt data
    let size = encodeMessageSize(dataSerialized.len)
    let buffer = size & dataSerialized
    await client.conn.send(buffer)

proc sendAll*[S, R](server: Server[S, R], data: S) {.async.} =
  await server.send(toSeq(server.clients.keys), data)

proc serving*[S, R](server: Server[S, R]): bool {.inline.} =
  server.isServing

proc getAddr*[S, R](server: Server[S, R]): (string, uint16) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  server.sock.getLocalAddr

proc getClientAddr*[S, R](server: Server[S, R], clientId: uint): (string, uint16) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  server.clients[clientId].conn.getPeerAddr

proc removeClient*[S, R](server: Server[S, R], clientId: uint) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let client = server.clients[clientId]
  client.conn.close()
  server.clients.del(clientId)

proc serve[S, R](server: Server[S, R]) {.async.} =
  while server.isServing:
    try:
      let conn = await server.sock.accept()
      let clientId = server.newClientId()
      let key = await server.exchangeKeys(clientId, conn)
      server.clients[clientId] = ClientRepr(conn, key)
      asyncCheck server.serveClient(clientId)
    except CatchableError:
      discard # this handles the case where an error is thrown because the server has been stopped, and ignores all other errors

proc serveClient[S, R](server: Server[S, R], clientId: uint) {.async.} =
  server.onConnect(clientId)
  defer:
    server.onDisconnect(clientId)
  let client = server.clients[clientId]
  try:
    while server.isServing:
      let size = await client.conn.recv(lenSize)
      let msgSize = decodeMessageSize(size)
      let buffer = await client.conn.recv(msgSize)
      # TODO: decrypt data
      let data = deserialize[R](buffer)
      server.onReceive(clientId, data)
  except CatchableError:
    if server.clients.hasKey(clientId):
      server.removeClient(clientId)

proc newClientId[S, R](server: Server[S, R]): uint =
  result = server.nextClientId
  server.nextClientId += 1

proc exchangeKeys[S, R](server: Server[S, R], clientId: uint, conn: AsyncSocket): Future[array[aesKeySize, byte]] {.async.} =
  discard # TODO

proc `=destroy`*[S, R](server: ServerObj[S, R]) =
  server.stop()
