from abc import abstractmethod


class HardwareWalletClientCS:

    @abstractmethod
    def sign_standard_tx(self, tx):
        pass

    @abstractmethod
    def sign_tx_with_auth(self, tx, auth):
        pass

    @abstractmethod
    def authorize_tx(self, tx_hash, path):
        pass

    @abstractmethod
    def close(self):
        pass

