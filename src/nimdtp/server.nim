import std/[asyncdispatch, asyncfutures, asyncnet, sequtils, tables]
import ./[crypto, util]

type
  ServerOnReceive[S, R] = proc (server: Server[S, R], clientId: int, data: R) {.closure.}
  ServerOnConnect[S, R] = proc (server: Server[S, R], clientId: int) {.closure.}
  ServerOnDisconnect[S, R] = proc (server: Server[S, R], clientId: int) {.closure.}

  ClientRepr = object
    conn: AsyncSocket
    key: AesKey

  ServerObj[S, R] = object
    isServing: bool
    sock: AsyncSocket
    clients: Table[int, ClientRepr]
    nextClientId: int
    onReceive: ServerOnReceive[S, R]
    onConnect: ServerOnConnect[S, R]
    onDisconnect: ServerOnDisconnect[S, R]

  Server*[S, R] = ref ServerObj[S, R]

proc exchangeKeys[S, R](server: Server[S, R], clientId: int, conn: AsyncSocket): Future[AesKey] {.async.} =
  discard # TODO

proc newClientId[S, R](server: Server[S, R]): int =
  result = server.nextClientId
  server.nextClientId += 1

proc serveClient[S, R](server: Server[S, R], clientId: int) {.async.} =
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
      let buffer = await client.conn.recv(int(msgSize))
      if buffer.len != int(msgSize):
        break
      # TODO: decrypt data
      let data = deserialize[R](buffer)
      if server.onReceive != nil:
        server.onReceive(server, clientId, data)
  except CatchableError:
    if server.isServing and server.clients.hasKey(clientId):
      server.removeClient(clientId)

proc serve[S, R](server: Server[S, R]) {.async.} =
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
  new(result)
  result.isServing = false
  result.clients = initTable[int, ClientRepr]()
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
  sock.bindAddr(Port(port), host)
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

proc send*[S, R](server: Server[S, R], clientIds: seq[int], data: S) {.async.} =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let dataSerialized = serialize(data)
  for clientId in clientIds:
    let client = server.clients[clientId]
    # TODO: encrypt data
    let size = encodeMessageSize(dataSerialized.len)
    let buffer = size & dataSerialized
    await client.conn.send(buffer)

proc send*[S, R](server: Server[S, R], clientId: int, data: S) {.async.} =
  await server.send(@[clientId], data)

proc sendAll*[S, R](server: Server[S, R], data: S) {.async.} =
  await server.send(toSeq(server.clients.keys), data)

proc serving*[S, R](server: Server[S, R]): bool {.inline.} =
  server.isServing

proc getAddr*[S, R](server: Server[S, R]): (string, uint16) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let address = server.sock.getLocalAddr()
  (address[0], address[1].uint16)

proc getClientAddr*[S, R](server: Server[S, R], clientId: int): (string, uint16) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let address = server.clients[clientId].conn.getPeerAddr()
  (address[0], address[1].uint16)

proc removeClient*[S, R](server: Server[S, R], clientId: int) =
  if not server.isServing:
    raise newException(DTPError, "server is not serving")
  let client = server.clients[clientId]
  client.conn.close()
  server.clients.del(clientId)

proc `=destroy`*[S, R](server: ServerObj[S, R]) =
  for client in server.clients.values:
    if client.conn != nil and not client.conn.isClosed:
      client.conn.close()
  if server.sock != nil and not server.sock.isClosed:
    server.sock.close()
