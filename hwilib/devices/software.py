# from ..errors import BadArgumentError, DeviceFailureError, common_err_msgs, handle_errors
import base64

from hwilib.devices.softwarelib.ipc import ipc_connect, ipc_send_and_get_response
from hwilib.devices.softwarelib.IpcMessage import (
    AUTHORIZE_TX,
    PING,
    SIGN_TX,
    IpcMessage,
)
from hwilib.devices.softwarelib.settings import LISTEN_PORT

from ..errors import ActionCanceledError, DeviceConnectionError, UnavailableActionError

# from ..errors import BadArgumentError, DeviceFailureError, common_err_msgs, handle_errors
from ..hwwclient import HardwareWalletClient


# This class extends the HardwareWalletClient for Ledger Nano S and Nano X specific things
class SoftwareClient(HardwareWalletClient):
    def __init__(self, path, password="", expert=False):
        super(SoftwareClient, self).__init__(path, password, expert)
        # Nothing special to do here

    # Must return a dict with the xpub
    # Retrieves the public key at the specified BIP 32 derivation path
    def get_pubkey_at_path(self, path):

        return None

    # Must return a hex string with the signed transaction
    # The tx must be in the combined unsigned transaction format
    # Current only supports segwit signing
    def sign_tx(self, tx, auth=""):
        sock = ipc_connect()

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the softwarelib device"
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

    # Must return a base64 encoded string with the signed message
    # The message can be any string
    def sign_message(self, message, keypath):
        sock = ipc_connect()

        if sock is None:
            raise DeviceConnectionError(
                "Unable to open a tcp socket with the software device"
            )

        message_b64 = base64.b64encode(message).decode("utf-8")
        data = message_b64 + "\n" + keypath
        msg = IpcMessage(AUTHORIZE_TX, data)

        resp = ipc_send_and_get_response(sock, msg)

        if resp is None:
            raise ActionCanceledError("Something wrong signing with software device")

        # Send PSBT back
        return resp.get_raw_value()

    def display_address(self, keypath, p2sh_p2wpkh, bech32):
        raise UnavailableActionError("Not available for software device")

    # Setup a new device
    def setup_device(self, label="", passphrase=""):
        raise UnavailableActionError("Not available for software device")

    # Wipe this device
    def wipe_device(self):
        raise UnavailableActionError("Not available for software device")

    # Restore device from mnemonic or xprv
    def restore_device(self, label="", word_count=24):
        raise UnavailableActionError("Not available for software device")

    # Begin backup process
    def backup_device(self, label="", passphrase=""):
        raise UnavailableActionError("Not available for software device")

    # Close the device
    def close(self):
        pass
        # self.dongle.close()

    # Prompt pin
    def prompt_pin(self):
        raise UnavailableActionError("Not available for software device")

    # Send pin
    def send_pin(self, pin):
        raise UnavailableActionError("Not available for software device")

    # Toggle passphrase
    def toggle_passphrase(self):
        raise UnavailableActionError("Not available for software device")


def enumerate(password=""):
    results = []

    sock = ipc_connect()

    if sock is None:
        return results

    if ipc_send_and_get_response(sock, IpcMessage(PING, "")) is None:
        return results

    # TODO: Ask some data to the softwarelib device

    d_data = {}
    d_data["type"] = "checksig"
    d_data["model"] = "checksig_software_wallet"
    d_data["path"] = "127.0.0.1:" + str(LISTEN_PORT)
    d_data["needs_pin_sent"] = False
    d_data["needs_passphrase_sent"] = False

    d_data["fingerprint"] = "deadbeef"

    # d_data['error'] = 'Not initialized'
    # d_data['code'] = DEVICE_NOT_INITIALIZED

    results.append(d_data)

    sock.close()
    return results
