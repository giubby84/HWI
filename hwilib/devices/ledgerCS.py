import struct

from hwilib.devices.btchip.btchipUtils import compress_public_key, bitcoinTransaction
from hwilib.devices.ledger import LedgerClient
from hwilib.hwwclientCS import HardwareWalletClientCS
from hwilib.serializations import CTransaction, hash160


class LedgerClientCS(LedgerClient, HardwareWalletClientCS):
    def __init__(self, path, password="", expert=False):
        super(LedgerClientCS, self).__init__(path, password, expert)

    def sign_standard_tx(self, tx):
        return super().sign_tx(tx)

    def sign_tx_with_auth(self, tx, auth):
        c_tx = CTransaction(tx.tx)
        tx_bytes = c_tx.serialize_with_witness()

        # Master key fingerprint
        master_fpr = hash160(compress_public_key(self.app.getWalletPublicKey('')["publicKey"]))[:4]
        # An entry per input, each with 0 to many keys to sign with
        all_signature_attempts = [[]] * len(c_tx.vin)

        # NOTE: We only support signing Segwit inputs, where we can skip over non-segwit
        # inputs, or non-segwit inputs, where *all* inputs are non-segwit. This is due
        # to Ledger's mutually exclusive signing steps for each type.
        segwit_inputs = []
        # Legacy style inputs
        legacy_inputs = []

        has_segwit = False
        has_legacy = False

        script_codes = [[]] * len(c_tx.vin)

        # Detect changepath, (p2sh-)p2(w)pkh only
        change_path = ''
        for txout, i_num in zip(c_tx.vout, range(len(c_tx.vout))):
            # Find which wallet key could be change based on hdsplit: m/.../1/k
            # Wallets shouldn't be sending to change address as user action
            # otherwise this will get confused
            for pubkey, path in tx.outputs[i_num].hd_keypaths.items():
                if struct.pack("<I", path[0]) == master_fpr and len(path) > 2 and path[-2] == 1:
                    # For possible matches, check if pubkey matches possible template
                    if hash160(pubkey) in txout.scriptPubKey or hash160(
                            bytearray.fromhex("0014") + hash160(pubkey)) in txout.scriptPubKey:
                        change_path = ''
                        for index in path[1:]:
                            change_path += str(index) + "/"
                        change_path = change_path[:-1]

        for txin, psbt_in, i_num in zip(c_tx.vin, tx.inputs, range(len(c_tx.vin))):

            seq = format(txin.nSequence, 'x')
            seq = seq.zfill(8)
            seq = bytearray.fromhex(seq)
            seq.reverse()
            seq_hex = ''.join('{:02x}'.format(x) for x in seq)

            if psbt_in.non_witness_utxo:
                segwit_inputs.append({"value": txin.prevout.serialize() + struct.pack("<Q",
                                                                                      psbt_in.non_witness_utxo.vout[
                                                                                          txin.prevout.n].nValue),
                                      "witness": True, "sequence": seq_hex})
                # We only need legacy inputs in the case where all inputs are legacy, we check
                # later
                ledger_prevtx = bitcoinTransaction(psbt_in.non_witness_utxo.serialize())
                legacy_inputs.append(self.app.getTrustedInput(ledger_prevtx, txin.prevout.n))
                legacy_inputs[-1]["sequence"] = seq_hex
                has_legacy = True
            else:
                segwit_inputs.append(
                    {"value": txin.prevout.serialize() + struct.pack("<Q", psbt_in.witness_utxo.nValue),
                     "witness": True, "sequence": seq_hex})
                has_segwit = True

            pubkeys = []
            signature_attempts = []

            scriptCode = b""
            witness_program = b""
            if psbt_in.witness_utxo is not None and psbt_in.witness_utxo.is_p2sh():
                redeemscript = psbt_in.redeem_script
                witness_program += redeemscript
            elif psbt_in.non_witness_utxo is not None and psbt_in.non_witness_utxo.vout[txin.prevout.n].is_p2sh():
                redeemscript = psbt_in.redeem_script
            elif psbt_in.witness_utxo is not None:
                witness_program += psbt_in.witness_utxo.scriptPubKey
            elif psbt_in.non_witness_utxo is not None:
                # No-op
                redeemscript = b""
                witness_program = b""
            else:
                raise Exception("PSBT is missing input utxo information, cannot sign")

            # Check if witness_program is script hash
            if len(witness_program) == 34 and witness_program[0] == 0x00 and witness_program[1] == 0x20:
                # look up witnessscript and set as scriptCode
                witnessscript = psbt_in.witness_script
                scriptCode += witnessscript
            elif len(witness_program) > 0:
                # p2wpkh
                scriptCode += b"\x76\xa9\x14"
                scriptCode += witness_program[2:]
                scriptCode += b"\x88\xac"
            elif len(witness_program) == 0:
                if len(redeemscript) > 0:
                    scriptCode = redeemscript
                else:
                    scriptCode = psbt_in.non_witness_utxo.vout[txin.prevout.n].scriptPubKey

            # Save scriptcode for later signing
            script_codes[i_num] = scriptCode

            # Find which pubkeys could sign this input (should be all?)
            for pubkey in psbt_in.hd_keypaths.keys():
                if hash160(pubkey) in scriptCode or pubkey in scriptCode:
                    pubkeys.append(pubkey)

            # Figure out which keys in inputs are from our wallet
            for pubkey in pubkeys:
                keypath = psbt_in.hd_keypaths[pubkey]
                if master_fpr == struct.pack("<I", keypath[0]):
                    # Add the keypath strings
                    keypath_str = ''
                    for index in keypath[1:]:
                        keypath_str += str(index) + "/"
                    keypath_str = keypath_str[:-1]
                    signature_attempts.append([keypath_str, pubkey])

            all_signature_attempts[i_num] = signature_attempts

        # Sign any segwit inputs
        if has_segwit:
            # import pprint
            # print(f"segwit_inputs = {pprint.pformat(segwit_inputs)}")
            # print(f"tx_bytes = {tx_bytes}")
            # print(f"script_code = {script_codes[0]}")
            # print(f"signature_attempt=\n{all_signature_attempts[0][0][0]}")
            # import pdb;pdb.set_trace()
            # Process them up front with all scriptcodes blank
            blank_script_code = bytearray()
            for i in range(len(segwit_inputs)):
                self.app.startUntrustedTransaction(i == 0, i, segwit_inputs, blank_script_code, c_tx.nVersion)

            # Number of unused fields for Nano S, only changepath and transaction in bytes req
            self.app.finalizeInput(b"DUMMY", -1, -1, change_path, tx_bytes)

            # For each input we control do segwit signature
            for i in range(len(segwit_inputs)):
                # Don't try to sign legacy inputs
                if tx.inputs[i].non_witness_utxo is not None:
                    continue
                for signature_attempt in all_signature_attempts[i]:
                    self.app.startUntrustedTransaction(False, 0, [segwit_inputs[i]], script_codes[i], c_tx.nVersion)
                    tx.inputs[i].partial_sigs[signature_attempt[1]] = self.app.untrustedHashSign(signature_attempt[0],
                                                                                                 auth, c_tx.nLockTime,
                                                                                                 0x01)
        elif has_legacy:
            first_input = True
            # Legacy signing if all inputs are legacy
            for i in range(len(legacy_inputs)):
                for signature_attempt in all_signature_attempts[i]:
                    assert (tx.inputs[i].non_witness_utxo is not None)
                    self.app.startUntrustedTransaction(first_input, i, legacy_inputs, script_codes[i], c_tx.nVersion)
                    self.app.finalizeInput(b"DUMMY", -1, -1, change_path, tx_bytes)
                    tx.inputs[i].partial_sigs[signature_attempt[1]] = self.app.untrustedHashSign(signature_attempt[0],
                                                                                                 auth, c_tx.nLockTime,
                                                                                                 0x01)
                    first_input = False

        # Send PSBT back
        return {'psbt': tx.serialize()}

    def authorize_tx(self, tx_hash, path):
        super().app.signMessageSign()
        sig = super().app.signMessageSign()
        return sig

    def close(self):
        super().close()
