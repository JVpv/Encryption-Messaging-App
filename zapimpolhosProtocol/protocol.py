from abc import ABC, abstractmethod
import base64
from base64 import b64encode, b64decode
import json

class ProtocolMessage(ABC):

    def __init__(self, msgType="", msgLength=0, msgValue="", msgAuthor="", msgKey="", msgIv="", msgPrivate=False):
        self.msgType = msgType
        self.msgLength = msgLength
        self.msgValue = msgValue
        self.msgAuthor = msgAuthor
        self.msgKey = msgKey
        self.msgIv = msgIv
        self.msgPrivate = msgPrivate

    def encode(self):
        data = json.dumps({
            "msgType": self.msgType,
            "msgLength": self.msgLength,
            "msgValue": self.msgValue,
            "msgAuthor": self.msgAuthor,
            "msgKey": self.msgKey,
            "msgIv": self.msgIv,
            "msgPrivate": self.msgPrivate
        })
        return data

    def decode(self, data):
        b64 = json.loads(data)
        self.msgType = b64["msgType"]
        self.msgLength = b64decode(b64["msgLength"] + '===')
        self.msgValue = b64decode(b64["msgValue"] + '===')
        self.msgAuthor = b64decode(b64["msgAuthor"] + '===')
        self.msgKey = b64decode(b64["msgKey"] + '===')
        self.msgIv = b64decode(b64["msgIv"] + '===')
        self.msgPrivate = b64["msgPrivate"]
        
    def __repr__(self):
        return f"{self.msgType} {self.msgValue} {self.msgAuthor}"

class UsernameRequest(ProtocolMessage):
    def __init__(self, username="", key="", iv=""):
        ProtocolMessage.__init__(self, msgType="USER", msgLength=b64encode(str(4+len(username)+len(key)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=username, msgKey=key, msgIv=iv)

class UsernameResponse(ProtocolMessage): 
    def __init__(self, type="", message="", key="", iv=""):
        ProtocolMessage.__init__(self, msgType=type.ljust(4), msgLength=b64encode(str(4+len(message)+len(key)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=message, msgKey=key, msgIv=iv)

class PasswordRequest(ProtocolMessage):
    def __init__(self, passwd="", key="", iv=""):
        ProtocolMessage.__init__(self, msgType="PASS", msgLength=b64encode(str(4+len(passwd)+len(key)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=passwd, msgKey=key, msgIv=iv)

class PasswordResponse(ProtocolMessage): 
    def __init__(self, type="", message="", key="", iv=""):
        ProtocolMessage.__init__(self, msgType=type.ljust(4), msgLength=b64encode(str(4+len(message)+len(key)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=message, msgKey=key, msgIv=iv)

class MessageRequest(ProtocolMessage):
    def __init__(self, msg="", key="", iv=""):
         ProtocolMessage.__init__(self, msgType="MESG", msgLength=b64encode(str(4+len(msg)+len(key)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=msg, msgKey=key, msgIv=iv)

class RetrieveRequest(ProtocolMessage):
    def __init__(self):
        ProtocolMessage.__init__(self, msgType="RETR", msgLength=b64encode(str(4)).decode("latin-1"))

class DisconnectRequest(ProtocolMessage):
    def __init__(self):
        ProtocolMessage.__init__(self, msgType="CLOS", msgLength=b64encode(str(4)).decode("latin-1"))

class MessageOrRetrieveOrDisconnectResponse(ProtocolMessage):
    def __init__(self, type="",message="", key="", iv=""):
        ProtocolMessage.__init__(self, msgType=type.ljust(4), msgLength=b64encode(str(4+len(message)+len(key)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=message, msgKey=key, msgIv=iv)

class PrivateMessageRequest(ProtocolMessage):
    def __init__(self, msg="", username="", key="", iv=""):
        ProtocolMessage.__init__(self, msgType="PRIV", msgLength=b64encode(str(4+len(msg)+len(key)+len(username)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=msg, msgKey=key, msgIv=iv)

class BroadcastRequest(ProtocolMessage):
    def __init__(self, msg="", username="", key="", iv=""):
         ProtocolMessage.__init__(self, msgType="BROD", msgLength=b64encode(str(4+len(msg)+len(key)+len(username)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=msg, msgKey=key, msgIv=iv)

class BroadcastOrPrivateResponse(ProtocolMessage):
    def __init__(self, type="", message="", username="", key="", iv="", private=False):
         ProtocolMessage.__init__(self, msgType=type.ljust(4), msgLength=b64encode(str(4+len(message)+len(key)+len(username)+len(iv)).encode("latin-1")).decode("latin-1"), msgValue=message, msgAuthor=username, msgKey=key, msgIv=iv, msgPrivate=private)