import std/[asyncdispatch, random, tables, times]
import unittest
import nimdtp/[client, server, crypto, util]

randomize()

const serverHost = "127.0.0.1"
const serverPort = 0
const sleepTime = 100

template sleep() =
  waitFor sleepAsync(sleepTime)

template time(name: static[string], body: untyped): untyped =
  let t = cpuTime()
  body
  echo "Time taken for ", name, ": ", cpuTime() - t

type
  ExpectMap = ref object
    expected: Table[string, int]
    observed: Table[string, int]

proc newExpectMap(): ExpectMap =
  new(result)
  result.expected = initTable[string, int]()
  result.observed = initTable[string, int]()

proc expect(map: ExpectMap, kind: string, count: int) =
  map.expected[kind] = count
  map.observed[kind] = 0

proc received(map: ExpectMap, kind: string) =
  map.observed[kind] = map.observed.getOrDefault(kind, 0) + 1

proc done(map: ExpectMap) =
  for kind in map.expected.keys:
    if map.expected[kind] != map.observed[kind]:
      echo "\"", kind, "\" expected ", map.expected[kind], ", got ", map.observed[kind]
    doAssert map.expected[kind] == map.observed[kind]
  doAssert map.expected == map.observed

proc `*`[I](bytes: array[I, int]): string =
  for value in bytes:
    result.add($char(value))

test "serialize and deserialize":
  type
    Foo = object
      id: int
      bar: string

  let value = Foo(id: 1, bar: "baz")
  let valueSerialized = serialize(value)
  doAssert valueSerialized == """{"id": 1, "bar": "baz"}"""
  let valueDeserialized = deserialize[Foo](valueSerialized)
  doAssert valueDeserialized == value

test "encode message size":
  doAssert encodeMessageSize(0) == *[0, 0, 0, 0, 0]
  doAssert encodeMessageSize(1) == *[0, 0, 0, 0, 1]
  doAssert encodeMessageSize(255) == *[0, 0, 0, 0, 255]
  doAssert encodeMessageSize(256) == *[0, 0, 0, 1, 0]
  doAssert encodeMessageSize(257) == *[0, 0, 0, 1, 1]
  doAssert encodeMessageSize(4311810305) == *[1, 1, 1, 1, 1]
  doAssert encodeMessageSize(4328719365) == *[1, 2, 3, 4, 5]
  doAssert encodeMessageSize(47362409218) == *[11, 7, 5, 3, 2]
  doAssert encodeMessageSize(1099511627775) == *[255, 255, 255, 255, 255]

test "decode message size":
  doAssert decodeMessageSize(*[0, 0, 0, 0, 0]) == 0
  doAssert decodeMessageSize(*[0, 0, 0, 0, 1]) == 1
  doAssert decodeMessageSize(*[0, 0, 0, 0, 255]) == 255
  doAssert decodeMessageSize(*[0, 0, 0, 1, 0]) == 256
  doAssert decodeMessageSize(*[0, 0, 0, 1, 1]) == 257
  doAssert decodeMessageSize(*[1, 1, 1, 1, 1]) == 4311810305
  doAssert decodeMessageSize(*[1, 2, 3, 4, 5]) == 4328719365
  doAssert decodeMessageSize(*[11, 7, 5, 3, 2]) == 47362409218
  doAssert decodeMessageSize(*[255, 255, 255, 255, 255]) == 1099511627775

test "crypto":
  let rsaMessage = "Hello, RSA!"
  time "new RSA key pair":
    let (publicKey, privateKey) = newRsaKeyPairSync()
  time "RSA encrypt":
    let rsaEncrypted = rsaEncryptSync(publicKey, rsaMessage)
  time "RSA decrypt":
    let rsaDecrypted = rsaDecryptSync(privateKey, rsaEncrypted)
  echo "Original string:  " & rsaMessage
  echo "Encrypted string: " & rsaEncrypted
  echo "Decrypted string: " & rsaDecrypted
  doAssert rsaDecrypted == rsaMessage
  doAssert rsaEncrypted != rsaMessage

  let aesMessage = "Hello, AES!"
  time "new AES key":
    let key = newAesKeySync()
  time "AES encrypt":
    let aesEncrypted = aesEncryptSync(key, aesMessage)
  time "AES decrypt":
    let aesDecrypted = aesDecryptSync(key, aesEncrypted)
  echo "Original string:  " & aesMessage
  echo "Encrypted string: " & aesEncrypted
  echo "Decrypted string: " & aesDecrypted
  doAssert aesDecrypted == aesMessage
  doAssert aesEncrypted != aesMessage

  time "new RSA key pair for encrypting AES key":
    let (publicKey2, privateKey2) = newRsaKeyPairSync()
  time "new AES key for being RSA encrypted":
    let key2 = newAesKeySync()
  time "encrypting AES key with RSA":
    let encryptedKey = rsaEncryptSync(publicKey2, $key2)
  time "decrypting AES key with RSA":
    let decryptedKey = rsaDecryptSync(privateKey2, encryptedKey).toAesKey
  doAssert $key2 == $decryptedKey
  doAssert $key2 != encryptedKey

  proc generateLargeMessage(size: int): seq[char] =
    result = newSeq[char](size)
    for i in 0..<size:
      result[i] = rand(char)

  proc toString(str: seq[char]): string =
    result = newStringOfCap(len(str))
    for ch in str:
      add(result, ch)

  let largeMessage = generateLargeMessage(65536).toString

  time "AES encrypt large message":
    let thing = aesEncryptSync(key2, largeMessage)
  echo "Encrypted long str len: ", thing.len

  # let rsaMessage = "Hello, RSA!"
  # echo "gen keys"
  # let (publicKey, privateKey) = waitFor newRsaKeyPair()
  # echo "encrypt"
  # let rsaEncrypted = waitFor rsaEncrypt(publicKey, rsaMessage)
  # echo "decrypt"
  # let rsaDecrypted = waitFor rsaDecrypt(privateKey, rsaEncrypted)
  # echo "Original string:  " & rsaMessage
  # echo "Encrypted string: " & rsaEncrypted
  # echo "Decrypted string: " & rsaDecrypted
  # doAssert rsaDecrypted == rsaMessage
  # doAssert rsaEncrypted != rsaMessage

  # let aesMessage = "Hello, AES!"
  # let key = waitFor newAesKey()
  # let aesEncrypted = waitFor aesEncrypt(key, aesMessage)
  # let aesDecrypted = waitFor aesDecrypt(key, aesEncrypted)
  # echo "Original string:  " & aesMessage
  # echo "Encrypted string: " & aesEncrypted
  # echo "Decrypted string: " & aesDecrypted
  # doAssert aesDecrypted == aesMessage
  # doAssert aesEncrypted != aesMessage

  # let (publicKey2, privateKey2) = waitFor newRsaKeyPair()
  # let key2 = waitFor newAesKey()
  # let encryptedKey = waitFor rsaEncrypt(publicKey2, $key2)
  # let decryptedKey = waitFor(rsaDecrypt(privateKey2, encryptedKey)).toAesKey
  # doAssert $key2 == $decryptedKey
  # doAssert $key2 != encryptedKey

test "server serving":
  let expected = newExpectMap()
  expected.expect("server receive", 0)
  expected.expect("server connect", 0)
  expected.expect("server disconnect", 0)

  proc onReceive(server: Server[int, string], clientId: int, data: string) =
    expected.received("server receive")
  
  proc onConnect(server: Server[int, string], clientId: int) =
    expected.received("server connect")

  proc onDisconnect(server: Server[int, string], clientId: int) =
    expected.received("server disconnect")

  let server = newServer[int, string](onReceive, onConnect, onDisconnect)
  doAssert not server.serving
  waitFor server.start(serverHost, serverPort)
  sleep
  doAssert server.serving
  echo "Server address: ", server.getAddr()
  server.stop()
  sleep
  doAssert not server.serving
  expected.done()

test "addresses":
  let expected = newExpectMap()
  expected.expect("server receive", 0)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", 0)
  expected.expect("client disconnected", 0)

  proc serverOnReceive(server: Server[int, string], clientId: int, data: string) =
    expected.received("server receive")
  
  proc serverOnConnect(server: Server[int, string], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[int, string], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[string, int], data: int) =
    expected.received("client receive")

  proc clientOnDisconnected(client: Client[string, int]) =
    expected.received("client disconnected")

  let server = newServer[int, string](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[string, int](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  doAssert server.getAddr() == client.getServerAddr()
  doAssert client.getAddr() == server.getClientAddr(0)
  client.disconnect()
  sleep
  server.stop()
  sleep
  expected.done()

test "send":
  let messageFromServer = 29275
  let messageFromClient = "Hello, server!"

  let expected = newExpectMap()
  expected.expect("server receive", 1)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", 1)
  expected.expect("client disconnected", 0)

  proc serverOnReceive(server: Server[int, string], clientId: int, data: string) =
    expected.received("server receive")
    doAssert clientId == 0
    doAssert data == messageFromClient
  
  proc serverOnConnect(server: Server[int, string], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[int, string], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[string, int], data: int) =
    expected.received("client receive")
    doAssert data == messageFromServer

  proc clientOnDisconnected(client: Client[string, int]) =
    expected.received("client disconnected")

  let server = newServer[int, string](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[string, int](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  waitFor server.sendAll(messageFromServer)
  waitFor client.send(messageFromClient)
  sleep
  client.disconnect()
  sleep
  server.stop()
  sleep
  expected.done()

test "large send":
  proc generateLargeMessage(size: int): seq[byte] =
    result = newSeq[byte](size)
    for i in 0..<size:
      result[i] = rand(byte)

  let messageFromServer = generateLargeMessage(rand(32768..<65536))
  let messageFromClient = generateLargeMessage(rand(16384..<32768))

  let expected = newExpectMap()
  expected.expect("server receive", 1)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", 1)
  expected.expect("client disconnected", 0)

  proc serverOnReceive(server: Server[seq[byte], seq[byte]], clientId: int, data: seq[byte]) =
    expected.received("server receive")
    doAssert clientId == 0
    doAssert data == messageFromClient
  
  proc serverOnConnect(server: Server[seq[byte], seq[byte]], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[seq[byte], seq[byte]], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[seq[byte], seq[byte]], data: seq[byte]) =
    expected.received("client receive")
    doAssert data == messageFromServer

  proc clientOnDisconnected(client: Client[seq[byte], seq[byte]]) =
    expected.received("client disconnected")

  let server = newServer[seq[byte], seq[byte]](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[seq[byte], seq[byte]](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  waitFor server.sendAll(messageFromServer)
  waitFor client.send(messageFromClient)
  sleep
  client.disconnect()
  sleep
  server.stop()
  sleep
  expected.done()

test "sending numerous messages":
  proc generateNumerousMessages(numMessages: int): seq[uint16] =
    result = newSeq[uint16](numMessages)
    for i in 0..<numMessages:
      result[i] = rand(uint16)

  let messagesFromServer = generateNumerousMessages(rand(64..<128))
  let messagesFromClient = generateNumerousMessages(rand(128..<256))

  let expected = newExpectMap()
  expected.expect("server receive", messagesFromClient.len)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", messagesFromServer.len)
  expected.expect("client disconnected", 0)

  var receivedFromServer: seq[uint16] = @[]
  var receivedFromClient: seq[uint16] = @[]

  proc serverOnReceive(server: Server[uint16, uint16], clientId: int, data: uint16) =
    expected.received("server receive")
    doAssert clientId == 0
    receivedFromClient.add(data)
  
  proc serverOnConnect(server: Server[uint16, uint16], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[uint16, uint16], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[uint16, uint16], data: uint16) =
    expected.received("client receive")
    receivedFromServer.add(data)

  proc clientOnDisconnected(client: Client[uint16, uint16]) =
    expected.received("client disconnected")

  let server = newServer[uint16, uint16](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[uint16, uint16](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  for serverMessage in messagesFromServer:
    waitFor server.sendAll(serverMessage)
  for clientMessage in messagesFromClient:
    waitFor client.send(clientMessage)
  sleep
  doAssert messagesFromServer == receivedFromServer
  doAssert messagesFromClient == receivedFromClient
  client.disconnect()
  sleep
  server.stop()
  sleep
  expected.done()

test "sending custom types":
  type
    Custom = object
      a: int
      b: string
      c: seq[string]

  let messageFromServer = Custom(a: 123, b: "Hello, custom server type!", c: @["first server item", "second server item"])
  let messageFromClient = Custom(a: 456, b: "Hello, custom client type!", c: @["#1 client item", "client item #2", "(3) client item"])

  let expected = newExpectMap()
  expected.expect("server receive", 1)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", 1)
  expected.expect("client disconnected", 0)

  proc serverOnReceive(server: Server[Custom, Custom], clientId: int, data: Custom) =
    expected.received("server receive")
    doAssert clientId == 0
    doAssert data == messageFromClient
  
  proc serverOnConnect(server: Server[Custom, Custom], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[Custom, Custom], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[Custom, Custom], data: Custom) =
    expected.received("client receive")
    doAssert data == messageFromServer

  proc clientOnDisconnected(client: Client[Custom, Custom]) =
    expected.received("client disconnected")

  let server = newServer[Custom, Custom](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[Custom, Custom](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  waitFor server.sendAll(messageFromServer)
  waitFor client.send(messageFromClient)
  sleep
  client.disconnect()
  sleep
  server.stop()
  sleep
  expected.done()

test "multiple clients":
  let messageFromServer = 29275
  let messageFromClient1 = "Hello from client #1!"
  let messageFromClient2 = "Goodbye from client #2!"
  var receivingMessageFromServer = false

  let expected = newExpectMap()
  expected.expect("server receive", 2)
  expected.expect("server connect", 2)
  expected.expect("server disconnect", 2)
  expected.expect("client 1 receive", 2)
  expected.expect("client 2 receive", 2)
  expected.expect("client disconnected", 0)

  proc serverOnReceive(server: Server[int, string], clientId: int, data: string) =
    expected.received("server receive")
    doAssert clientId == 0 or clientId == 1
    if clientId == 0:
      doAssert data == messageFromClient1
    elif clientId == 1:
      doAssert data == messageFromClient2
    asyncCheck server.send(clientId, data.len)

  proc serverOnConnect(server: Server[int, string], clientId: int) =
    expected.received("server connect")
    doAssert clientId == 0 or clientId == 1

  proc serverOnDisconnect(server: Server[int, string], clientId: int) =
    expected.received("server disconnect")
    doAssert clientId == 0 or clientId == 1

  proc client1OnReceive(client: Client[string, int], data: int) =
    expected.received("client 1 receive")
    if receivingMessageFromServer:
      doAssert data == messageFromServer
    else:
      doAssert data == messageFromClient1.len

  proc client2OnReceive(client: Client[string, int], data: int) =
    expected.received("client 2 receive")
    if receivingMessageFromServer:
      doAssert data == messageFromServer
    else:
      doAssert data == messageFromClient2.len

  proc clientOnDisconnected(client: Client[string, int]) =
    expected.received("client disconnected")

  let server = newServer[int, string](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client1 = newClient[string, int](client1OnReceive, clientOnDisconnected)
  waitFor client1.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client 1 address: ", client1.getAddr()
  doAssert server.getAddr() == client1.getServerAddr()
  doAssert client1.getAddr() == server.getClientAddr(0)
  let client2 = newClient[string, int](client2OnReceive, clientOnDisconnected)
  waitFor client2.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client 2 address: ", client2.getAddr()
  doAssert server.getAddr() == client2.getServerAddr()
  doAssert client2.getAddr() == server.getClientAddr(1)
  waitFor client1.send(messageFromClient1)
  sleep
  waitFor client2.send(messageFromClient2)
  sleep
  receivingMessageFromServer = true
  waitFor server.sendAll(messageFromServer)
  sleep
  client1.disconnect()
  sleep
  client2.disconnect()
  sleep
  server.stop()
  sleep
  expected.done()

test "remove client":
  let expected = newExpectMap()
  expected.expect("server receive", 0)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", 0)
  expected.expect("client disconnected", 1)

  proc serverOnReceive(server: Server[int, string], clientId: int, data: string) =
    expected.received("server receive")
  
  proc serverOnConnect(server: Server[int, string], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[int, string], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[string, int], data: int) =
    expected.received("client receive")

  proc clientOnDisconnected(client: Client[string, int]) =
    expected.received("client disconnected")

  let server = newServer[int, string](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[string, int](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  doAssert client.connected
  server.removeClient(0)
  sleep
  doAssert not client.connected
  server.stop()
  sleep
  expected.done()

test "stop server while client connected":
  let expected = newExpectMap()
  expected.expect("server receive", 0)
  expected.expect("server connect", 1)
  expected.expect("server disconnect", 1)
  expected.expect("client receive", 0)
  expected.expect("client disconnected", 1)

  proc serverOnReceive(server: Server[int, string], clientId: int, data: string) =
    expected.received("server receive")
  
  proc serverOnConnect(server: Server[int, string], clientId: int) =
    expected.received("server connect")

  proc serverOnDisconnect(server: Server[int, string], clientId: int) =
    expected.received("server disconnect")

  proc clientOnReceive(client: Client[string, int], data: int) =
    expected.received("client receive")

  proc clientOnDisconnected(client: Client[string, int]) =
    expected.received("client disconnected")

  let server = newServer[int, string](serverOnReceive, serverOnConnect, serverOnDisconnect)
  waitFor server.start(serverHost, serverPort)
  sleep
  let serverAddr = server.getAddr()
  echo "Server address: ", serverAddr
  let client = newClient[string, int](clientOnReceive, clientOnDisconnected)
  waitFor client.connect(serverAddr[0], serverAddr[1])
  sleep
  echo "Client address: ", client.getAddr()
  doAssert server.serving
  doAssert client.connected
  server.stop()
  doAssert not server.serving
  sleep
  doAssert not client.connected
  expected.done()
