# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'client.ui'
#
# Created by: PyQt5 UI code generator 5.13.2
#
# WARNING! All changes made in this file will be lost!

######################################################################################
#                                                                                    #         
# Trabalho de Redes Convergentes - AV2.                                              #
#                                                                                    #
# O trabalho consiste em uma aplicação de bate-papo cliente-servidor onde todas      #
# as mensagens são criptografadas com RSA e AES. A interface do cliente foi          #
# feita usando o pyqt5 designer, e transformada em código por CLI.                   #
#                                                                                    #        
# O protocolo contém as seguintes mensagens:                                         #
# REQUISIÇÃO:                                                                        #
# * USER <username>: Envio do nome de usuário do chat.                               #
# * PASS <senha>: Senha de acesso ao chat.                                           #
# * MESG <mensagem>: Mensagem a ser enviada aos participantes do chat.               #
# * RETR: Listar os participantes do chat.                                           #
# * PRIV <username> <mensagem>: Envia uma mensagem privada a um determinado usuário. #
# * CLOS: Encerra a comunicação do cliente com o servidor.                           #
# * BROD <username> <mensagem>: Quando o servidor receber uma mensagem do tipo MESG, # 
# * ele enviará uma mensagem BROD para os demais clientes com o nome de usuário que  #
# * enviou a mensagem originalmente e a mensagem propriamente dita.                  #
#                                                                                    #
# RESPOSTA:                                                                          #
# * OK: Mensagem de confirmação. Esta mensagem é enviada para o cliente caso a       #
# solicitação seja bem sucedida. Caso necessite ser enviada uma resposta a um        #
# comando, e.g. RETR, esta mensagem servirá como um container de resposta.           #
# * ERR: Mensagem de erro. Esta mensagem é enviada para o cliente caso a solicitação # 
# seja mal sucedida.                                                                 #
#                                                                                    #
# Os usuários são cadastrados na classe handler.py.                                  #
#                                                                                    #
# Para fazer uma requisição do tipo RETR, o usuário deve enviar uma mensagem escrita #
# ">@" (sem as aspas). Para uma mensagem do tipo BROD, é necessário enviar uma       #
# mensagem precedida por ">usuario " (sem aspas) onde usuario é o destinatário da    #
# mensagem. O espaço após a informação do usuário é obrigatório. Finalmente, uma     #
# mensagem do tipo CLOS é quando se envia uma mensagem escrita "/quit".              #
#                                                                                    #
# José Vítor Prado Varela - 1610362                                                  #
#                                                                                    #
######################################################################################

import sys, time
from sys import exit
import socket
import threading
import zapimpolhosProtocol.protocol as zpp
import base64
from base64 import b64decode, b64encode
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QTextCursor
from datetime import datetime
from PyQt5.QtCore import QThread, QThreadPool, pyqtSignal
from Crypto.Cipher import PKCS1_OAEP, DES, AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = "localhost"
PORT = 1998

class Ui_MainWindow(object):

    # Variáveis auxiliares para a classe
    logged = False
    unlocked = False
    writeLog = ""
    log = ""
    username = ""

    # Aqui é feita a conexão do client com o servidor.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print("Conectado!")

    # Para a criação das chaves RSA foi realizado o seguinte processo:
    # - Baixar OpenSSL
    # - Adicionar openssl para o bash
    # - Navegar no terminal para a pasta do projeto
    # - Executar o comando "openssl genrsa -out key.pem 2048" -> Cria o arquivo key.pem, que é a chave privada.
    # - Executar o comando "openssl rsa -in key.pem -outform PEM -pubout -out public.pem" -> Cria o arquivo public.pem, que é a chave pública.
    # Agora abrimos os arquivos.
    privateKey = RSA.import_key(open("key.pem").read())
    publicKey = RSA.import_key(open("public.pem").read())
    cryptRSA = PKCS1_OAEP.new(publicKey)
    decryptRSA = PKCS1_OAEP.new(privateKey)

    # Em seguida, é criada a chave e inicializada a cifra do AES. 

    # Por simplicidade, de fato todos os clientes já terão as chaves pública e privada do RSA para serem utilizadas, mas usaremos as que
    # recebemos do servidor (que são as mesmas, mas caso não fossem, funcionaria igual).

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.chatLog = QtWidgets.QTextEdit(self.centralwidget)
        self.chatLog.setGeometry(QtCore.QRect(0, 0, 801, 471))
        self.chatLog.setObjectName("textEdit")
        self.chatLog.setReadOnly(True)
        chatFont = QtGui.QFont()
        chatFont.setFamily("Courier")
        chatFont.setPointSize(10)
        self.chatLog.setCurrentFont(chatFont)
        self.chatLog.moveCursor(QTextCursor.End)
        self.msgInput = QtWidgets.QLineEdit(self.centralwidget)
        self.msgInput.setGeometry(QtCore.QRect(10, 510, 771, 22))
        self.msgInput.setObjectName("lineEdit")
        self.msgInput.setFont(chatFont)
        self.msgInput.returnPressed.connect(self.enviarMensagem)
        self.cmdLabel = QtWidgets.QLabel(self.centralwidget)
        self.cmdLabel.setGeometry(QtCore.QRect(10, 480, 280, 31))
        labelFont = QtGui.QFont()
        labelFont.setPointSize(12)
        self.cmdLabel.setFont(labelFont)
        self.cmdLabel.setObjectName("label")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName("menubar")
        self.menuArquivo = QtWidgets.QMenu(self.menubar)
        self.menuArquivo.setObjectName("menuArquivo")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.actionSalvar = QtWidgets.QAction(MainWindow)
        self.actionSalvar.setObjectName("actionSalvar")
        self.actionFazer_logout = QtWidgets.QAction(MainWindow)
        self.actionFazer_logout.setObjectName("actionFazer_logout")
        self.menuArquivo.addAction(self.actionSalvar)
        self.menuArquivo.addAction(self.actionFazer_logout)
        self.menubar.addAction(self.menuArquivo.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)


    def enviarMensagem(self):
        aesKey = get_random_bytes(16)
        cryptAES = AES.new(aesKey, AES.MODE_CBC)
        iv = b64encode(cryptAES.iv).decode('latin-1')
        cipherKey = self.cryptRSA.encrypt(aesKey)
        if self.logged:
            if self.unlocked:
                if self.msgInput.text() != "":
                    msg = self.msgInput.text()
                    ciphertext = cryptAES.encrypt(pad(msg.encode('latin-1'), AES.block_size))
                    msgRequest = zpp.MessageRequest(msg=b64encode(ciphertext).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                    self.s.sendall(bytes(msgRequest, encoding="latin-1"))
                    self.writeLog += "(" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ")" + self.username + ":" + self.msgInput.text() + "\n"
                    self.log += "<font color='green' size='6'>" + "(" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ") Eu: </font><font size='6'>" + self.msgInput.text() + "</font>" + "<br>"
                    self.chatLog.setText(self.log)
                    self.msgInput.setText("")
            else:
                passwd = self.msgInput.text()
                ciphertext = cryptAES.encrypt(pad(passwd.encode('latin-1'), AES.block_size))
                pwRequest = zpp.PasswordRequest(passwd=b64encode(ciphertext).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
                self.s.sendall(bytes(pwRequest, encoding="latin-1"))
                data = self.s.recv(1024)
                pResponse = zpp.PasswordResponse(data)
                if pResponse.msgType.strip() == "ERR":
                    print("Ocorreu um erro ao tentar enviar sua senha")
                else:
                    t = threading.Thread(target=self.handle_received_message, args=(self.s,))
                    t.start()
                    
                    self.cmdLabel.setText(QtCore.QCoreApplication.translate("MainWindow", "Digite uma mensagem: "))
                    self.unlocked = True
                    self.msgInput.setText("")

        else:
            self.username = self.msgInput.text()
            ciphertext = cryptAES.encrypt(pad(self.username.encode('latin-1'), AES.block_size))
            uname = zpp.UsernameRequest(username=b64encode(ciphertext).decode("latin-1"), key=b64encode(cipherKey).decode("latin-1"), iv=iv).encode()
            self.s.sendall(bytes(uname, encoding="latin-1"))
            data = self.s.recv(1024)
            uResponse = zpp.UsernameResponse(data)
            if uResponse.msgType.strip() == "ERR":
                print("Ocorreu um erro ao tentar enviar seu usuário.")
            else:
                self.cmdLabel.setText(QtCore.QCoreApplication.translate("MainWindow", "Digite sua senha: "))
                self.logged = True
                self.msgInput.setText("")

    def handle_received_message(self, sock):
        while sock._closed == False:
            data = sock.recv(1024)
            response = zpp.BroadcastOrPrivateResponse()
            response.decode(data)
            print("Autor:")
            print(response.msgAuthor)
            if response.msgValue != "":
                key = self.decryptRSA.decrypt(response.msgKey.strip())
                cipher = AES.new(key, AES.MODE_CBC, response.msgIv)
                msg = unpad(cipher.decrypt(response.msgValue), AES.block_size).decode('latin-1')
                if response.msgType.strip() == "OK" and response.msgAuthor != b"":
                    author = unpad(cipher.decrypt(response.msgAuthor), AES.block_size).decode('latin-1')
                    if not data: break
                    if response.msgPrivate == False:
                        self.writeLog += "(" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ") " + author + ": " + msg
                        self.log += "<font color='blue' size='6'>" + "(" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ") " + author + ":</font> <font size='6'>" + msg + "</font><br>"
                    else:
                        self.writeLog += "(" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ") " + author + ": " + msg
                        self.log += "<font color='purple' size='6'>" + "(" + datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ") " + author + ":</font> <font size='6'>" + msg + "</font><br>"
                
                if response.msgType.strip() == "OK" and response.msgAuthor == b"":
                    self.writeLog += msg + "\n"
                    self.log += "<font color='orange' size='6'>" + msg + "</font><br>"
                    if msg == "Goodbye.": 
                        sock.close()
                        
                else:
                    self.writeLog += msg + "\n"
                    self.writeLog += "<font color='red' size='6'>" + msg + "</font><br>"
        

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Zapimpolhos"))
        self.cmdLabel.setText(_translate("MainWindow", "Digite seu nome de usuário:"))
        self.menuArquivo.setTitle(_translate("MainWindow", "Arquivo"))
        self.actionSalvar.setText(_translate("MainWindow", "Salvar log"))
        self.actionFazer_logout.setText(_translate("MainWindow", "Fazer logout"))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setStyle("Fusion")
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())