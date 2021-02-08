import socket
from handler import ServerHandler

HOST = ""
PORT = 1998

try:
    svHandler = ServerHandler(HOST, PORT)
    svHandler.start()
    svHandler.join()

except KeyboardInterrupt:
    print("")
    print("Encerrando o servidor...")
    svHandler.stop()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))


print("Goodbye.")