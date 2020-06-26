import base64

from hwilib.devices.checksig import ChecksigClient
from hwilib.devices.checksiglib.ipc import ipc_connect, ipc_send_and_get_response
from hwilib.devices.checksiglib.ipc_message import IpcMessage, SIGN_TX
from hwilib.errors import DeviceConnectionError, ActionCanceledError
from hwilib.hwwclientCS import HardwareWalletClientCS


class ChecksigClientCS(ChecksigClient, HardwareWalletClientCS):
    def __init__(self, path, password="", expert=False):
        super(ChecksigClientCS, self).__init__(path, password, expert)

    def sign_standard_tx(self, tx):
        return super().sign_tx(tx)

    def authorize_tx(self, tx_hash, path):
        return super().sign_message(tx_hash, path)

    def sign_tx_with_auth(self, tx, auth):
        sock = ipc_connect(self.port)

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the software device"
            )

        serialized_psbt = tx.serialize()
        auth_b64 = base64.b64encode(auth).decode("utf-8")
        data = serialized_psbt + "\n" + auth_b64
        msg = IpcMessage(SIGN_TX, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("Something wrong signing with software device")

        # Send PSBT back
        return {"psbt": resp.get_raw_value()}

    def close(self):
        super().close()

