import base64
from typing import Optional


SIGN_TX = "sign"
AUTHORIZE_TX = "auth"
RESP = "resp"
PING = "ping"


class IpcMessage:
    def __init__(self, cmd: str, value: str):
        self._cmd = cmd
        self._value = value

    def get_cmd(self):
        return self._cmd

    def get_raw_value(self):
        return self._value

    @staticmethod
    def get_cmd_msg_size():
        return 4

    @staticmethod
    def get_size_msg_size():
        return 8
