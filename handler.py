import zapimpolhosProtocol.protocol as zpp
import base64
from Crypto.Cipher import PKCS1_OAEP, DES, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from threading import Thread
from socket import socket, AF_INET, SOCK_STREAM

users = [
    {
        "username": "zevitor",
        "passwd": "12345" 
    },
    {
        "username": "luciana",
        "passwd": "030319"
    },
    {
        "username": "ednaldo",
        "passwd": "pereira"
    }
]

class ServerHandler(Thread):

    def __init__(self, host, port):
        Thread.__init__(self)
        self.host = host
        self.port = port
        self.connections = []
        self.active = True

    def run(self):
        with socket(AF_INET, SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(5)
        
            while self.active:
                print(f"Aguardando novas conexões...")

                conn, addr = s.accept()
                
                ch = ConnectionHandler(conn, addr, self)
                self.connections.append(ch)
                ch.start()

        # Adicionar o código solicitando o fechamento das conexões com os clientes

    def notify_all_connections(self, from_addr, mesg="", user=""):
        rsaKey = RSA.import_key(open("public.pem").read())
        cryptRSA = PKCS1_OAEP.new(rsaKey)
        aesKey = get_random_bytes(16)
        cryptAES = AES.new(aesKey, AES.MODE_CBC)
        iv = b64encode(cryptAES.iv).decode('latin-1')
        cipherKey = cryptRSA.encrypt(aesKey)
        for client in self.connections:
            if client.addr != from_addr and mesg != ">@" and mesg != "/quit":
                if mesg[0] == ">":
                    for c in range(len(mesg)):
                        if mesg[c] == " ":
                            to = mesg[1:c]
                            mesg = mesg[c+1:]
                            break
                    print(client.username.strip() == to)
                    if client.username.strip() == to:
                        ciphertext = cryptAES.encrypt(pad(mesg.encode('latin-1'), AES.block_size))
                        cipherAuthor = cryptAES.encrypt(pad(user.encode('latin-1'), AES.block_size))
                        response = zpp.BroadcastOrPrivateResponse(type="OK", message=b64encode(ciphertext).decode("latin-1"), username=b64encode(cipherAuthor).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv, private=True).encode()
                        client.conn.sendall(bytes(response, encoding="latin-1")) 
                if mesg == "/quit":
                    ciphertext = cryptAES.encrypt(pad("<Desconectado>".encode('latin-1'), AES.block_size))
                    cipherAuthor = cryptAES.encrypt(pad(user.encode('latin-1'), AES.block_size))
                    response = zpp.BroadcastOrPrivateResponse(type="OK", message=b64encode(ciphertext).decode("latin-1"), username=b64encode(cipherAuthor).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                    client.conn.sendall(bytes(response, encoding="latin-1")) 
                else: 
                    ciphertext = cryptAES.encrypt(pad(mesg.encode('latin-1'), AES.block_size))
                    cipherAuthor = cryptAES.encrypt(pad(user.encode('latin-1'), AES.block_size))
                    response = zpp.BroadcastOrPrivateResponse(type="OK", message=b64encode(ciphertext).decode("latin-1"), username=b64encode(cipherAuthor).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                    client.conn.sendall(bytes(response, encoding="latin-1"))
                 
            if mesg == ">@":
                userList = ""
                for clientHere in self.connections:
                    userList += " " + clientHere.username.strip() + ","
                userList = userList[:-1]
                userList = userList.strip()
                if client.addr == from_addr:
                    try:
                        ciphertext = cryptAES.encrypt(pad(userList.encode('latin-1'), AES.block_size))
                        request = zpp.MessageOrRetrieveOrDisconnectResponse(type="OK", message=b64encode(ciphertext).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                        client.conn.sendall(bytes(request, encoding="latin-1"))
                    except Exception:
                        ciphertext = cryptAES.encrypt(pad("Não foi possível retornar os usuários.".encode('latin-1'), AES.block_size))
                        request = zpp.MessageOrRetrieveOrDisconnectResponse(type="ERR", message=b64encode(ciphertext).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                        client.conn.sendall(bytes(request, encoding="latin-1"))
            if mesg == "/quit" and client.addr == from_addr:
                ciphertext = cryptAES.encrypt(pad("Goodbye.".encode('latin-1'), AES.block_size))
                request = zpp.MessageOrRetrieveOrDisconnectResponse(type="OK", message=b64encode(ciphertext).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                client.conn.sendall(bytes(request, encoding="latin-1"))
                self.connections.remove(client)

    def stop(self):
        self.active = False

class ConnectionHandler(Thread): 

    def __init__(self, conn, addr, callback):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.callback = callback
        self.active = True
        self.username = ""
        self.passwd = ""

    def run(self):
        print(f"Cliente {self.addr} conectado! \n")

        privateKey = RSA.import_key(open("key.pem").read())
        decryptRSA = PKCS1_OAEP.new(privateKey)

        data = self.conn.recv(1024)
        usernameRequest = zpp.UsernameRequest()
        usernameRequest.decode(data)
        if usernameRequest.msgType.strip() != "USER":
            # Cuide do erro
            print("Deu um erro ao enviar o usuário")
        else:
            key = decryptRSA.decrypt(usernameRequest.msgKey.strip())
            cipher = AES.new(key, AES.MODE_CBC, usernameRequest.msgIv)
            self.username = unpad(cipher.decrypt(usernameRequest.msgValue), AES.block_size).decode('latin-1')
            found = False
            for user in users:
                if user["username"] == self.username:
                    found = True
                    break
            if found:
                response = zpp.UsernameResponse("OK", b64encode("Por favor envie a senha.".encode("latin-1")).decode("latin-1")).encode() 
            else:
                response = zpp.UsernameResponse("ERR", b64encode("Usuário inválido.".encode("latin-1")).decode("latin-1")).encode()
            self.conn.sendall(bytes(response, encoding="latin-1"))
            
        data = self.conn.recv(1024)
        passwdRequest = zpp.PasswordRequest()
        passwdRequest.decode(data)
        matched = False
        if passwdRequest.msgType.strip() != "PASS":
            # Erro
            ...
        else:
            key = decryptRSA.decrypt(passwdRequest.msgKey)
            cipher = AES.new(key, AES.MODE_CBC, passwdRequest.msgIv)
            self.passwd = unpad(cipher.decrypt(passwdRequest.msgValue), AES.block_size).decode("latin-1")
            for user in users:
                if user["username"] == self.username and user["passwd"] == self.passwd:
                    matched = True
                    break
            if matched:
                response = zpp.UsernameResponse("OK", b64encode("Bem vinde à baderna!!".encode("latin-1")).decode("latin-1")).encode()
            else:
                response = zpp.UsernameResponse("ERR", b64encode("Senha inválida.".encode("latin-1")).decode("latin-1")).encode()
            self.conn.sendall(bytes(response, encoding="latin-1"))

                
        with self.conn:
            while self.active:
                data = self.conn.recv(1024)
                msgRequest = zpp.MessageRequest()
                msgRequest.decode(data)
                if msgRequest.msgType.strip() == "MESG":
                    key = decryptRSA.decrypt(msgRequest.msgKey)
                    cipher = AES.new(key, AES.MODE_CBC, msgRequest.msgIv)
                    mesg = unpad(cipher.decrypt(msgRequest.msgValue), AES.block_size).decode("latin-1")
                    if not data: break
                    print(f"Recebida mensagem de {self.addr}: {mesg}")
                    self.callback.notify_all_connections(from_addr=self.addr, mesg=mesg, user=self.username)