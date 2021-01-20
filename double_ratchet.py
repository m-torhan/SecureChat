from __future__ import annotations
import curve25519
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import HMAC, SHA256

class DoubleRatchetState(object):
    '''
    Class containg all parameters of double ratchet state.
    '''
    def __init__(self, dhs: bytes, dhr: bytes, rk: bytes, cks: bytes, ckr: bytes):
        self.dhs = dhs              # DH ratchet key pair
        self.dhr = dhr              # DH ratchet received public key
        self.rk = rk                # root key
        self.cks = cks              # sending chain key
        self.ckr = ckr              # receiving chain key
        self.ns = 0                 # message number sending chain
        self.nr = 0                 # message number receiving chain
        self.pn = 0                 # previous chain size
        self.mkskipped = {}         # skipped message keys

class DoubleRatchetHeader(object):
    '''
    Header of double ratchet Packet.
    '''
    def __init__(self, dh: bytes, pn: int, n: int) -> DoubleRatchetHeader:
        '''
        DoubleRatchetHeader constructor.
        '''
        self.dh = dh
        self.pn = pn
        self.n =  n
    
    def to_bytes(self) -> bytes:
        '''
        Converts header to byte array.
        '''
        return self.dh + int.to_bytes(self.pn, 4, byteorder='big') + int.to_bytes(self.n, 4, byteorder='big')
    
    @staticmethod
    def from_bytes(byte_array: bytes) -> DoubleRatchetHeader:
        '''
        Converts byte array to DoubleRatchetHeader
        '''
        return DoubleRatchetHeader(byte_array[:-8], int.from_bytes(byte_array[-8:-4], byteorder='big'), int.from_bytes(byte_array[-4:], byteorder='big'))
class DoubleRatchetPacket(object):
    '''
    Double ratchet packet that is used in secure data exchange.
    '''
    def __init__(self, header:  DoubleRatchetHeader, payload: bytes) -> DoubleRatchetPacket:
        '''
        DoubleRatchetPacket constructor.
        '''
        self.__header = header
        self.__payload = payload
    
    @property
    def header(self) -> DoubleRatchetHeader:
        '''
        Returns packet's header.
        '''
        return self.__header
        
    @property
    def payload(self) -> bytes:
        '''
        Returns packet's payload.
        '''
        return self.__payload
    
    def to_bytes(self) -> bytes:
        '''
        Converts packet to byte array.
        '''
        return self.__header.to_bytes() + self.__payload
    
    @staticmethod
    def from_bytes(byte_array: bytes) -> DoubleRatchetPacket:
        '''
        Converts byte array to DoubleRatchetPacket
        '''
        return DoubleRatchetPacket(DoubleRatchetHeader.from_bytes(byte_array[:40]), byte_array[40:])

class DoubleRatchetKeyPair(object):
    '''
    Pair of public and private key.
    '''
    def __init__(self, public_key: bytes, private_key: bytes):
        '''
        DoubleRatchetKeyPair constructor.
        '''
        self.__public_key = public_key
        self.__private_key = private_key
    
    @property
    def public_key(self) -> bytes:
        '''
        Returns public key.
        '''
        return self.__public_key
        
    @property
    def private_key(self) -> bytes:
        '''
        Returns private key.
        '''
        return self.__private_key
    
    def get_agreement(self, public_key: bytes) -> bytes:
        '''
        Returns calculated agreement.
        '''
        return curve25519.calculateAgreement(public_key, self.__private_key)

class DoubleRatchetKeyPairGenerator(object):
    '''
    Class used to generate pair of keys using eliptic curve.
    '''
    @staticmethod
    def generate_key_pair():
        '''
        Generates and returns pair of keys.
        '''
        r = get_random_bytes(32)
        return DoubleRatchetKeyPair(curve25519.generatePublicKey(r), curve25519.generatePrivateKey(r))

class DoubleRatchet(object):
    '''
    Class that handles key management using double ratchet algorithm.
    '''
    # ratchet parameters
    MAX_SKIP = 10
    app_specific_info = bytes(b'\x00')*32
    mac_size = 16
    fixed_nonce = b'\x24\x7b\x67\x10\x19\x75\x65\x41\x10\x2e'

    @staticmethod
    def create_initiator_state(sk: bytes, pk: bytes) -> DoubleRatchetState:
        '''
        Creates state for communication initiator.
        '''
        key_pair = DoubleRatchetKeyPairGenerator.generate_key_pair()
        kdf_rk = DoubleRatchet.__kdf_rk(sk, DoubleRatchet.__dh(key_pair, pk))
        return DoubleRatchetState(key_pair, pk, *kdf_rk, None)
    
    @staticmethod
    def create_receiver_state(key_pair: DoubleRatchetKeyPair, sk: bytes) -> DoubleRatchetState:
        '''
        Creates state for communication receiver.
        '''
        return DoubleRatchetState(key_pair, None, sk, None, None)
    
    @staticmethod
    def ratchet_encrypt(state: DoubleRatchetState, plaintext: str, ad: bytes) -> DoubleRatchetPacket:
        '''
        Handles plaintext encryption.
        '''
        # compute keys
        kdf = DoubleRatchet.__kdf_ck(state.cks)
        state.cks  = kdf[0]
        mk = kdf[1]
        # create header
        header = DoubleRatchetHeader(state.dhs.public_key, state.pn, state.ns)
        state.ns +=  1
        # create packet with encryptet text
        return DoubleRatchetPacket(header, DoubleRatchet.__encrypt(mk, plaintext.encode(), bytes(0)))
    
    @staticmethod
    def ratchet_decrypt(state: DoubleRatchetState, packet: DoubleRatchetPacket, ad: bytes) -> bytes:
        '''
        Handles ciphertext decryption.
        '''
        # if the message corresponds to a skipped message key - decrypt the message and delete the message key
        plaintext = DoubleRatchet.__try_skipped_message_keys(state, packet, ad)
        if (plaintext != None):
            return plaintext
        elif state.dhr == None or packet.header.dh != state.dhr:
            # if a new ratchet key has been received this function stores any skipped message keys from the receiving chain
            DoubleRatchet.__skip_message_keys(state, packet.header.pn)
            DoubleRatchet.__dh_ratchet(state, packet.header)
        
        DoubleRatchet.__skip_message_keys(state, packet.header.n)
        # compute keys
        kdf = DoubleRatchet.__kdf_ck(state.ckr)
        state.ckr = kdf[0]
        mk = kdf[1]
        state.nr += 1
        # decrypt ciphertext and return it
        return DoubleRatchet.__decrypt(mk, packet.payload, ad + packet.header.to_bytes())

    @staticmethod
    def __try_skipped_message_keys(state: DoubleRatchetState, packet:  DoubleRatchetPacket, ad: bytes) -> bytes:
        '''
        Tries to decrypt message using skipped keys.
        '''
        if packet.header.dh not in state.mkskipped.keys():
            return None
        mk = state.mkskipped[packet.header.dh]
        if packet.header.n not in mk.keys():
            return None
        mk = mk[packet.header.n]
        # if key was used - delete it
        del state.mkskipped[packet.header.dh][packet.header.n]

        return DoubleRatchet.__decrypt(mk, packet.payload, ad + packet.header.to_bytes())

    @staticmethod
    def __skip_message_keys(state: DoubleRatchetState, until: int):
        '''
        Skips key and adds it to skipped keys dictionary.
        '''
        if state.nr + DoubleRatchet.MAX_SKIP < until:
            raise Exception('MAX_SKIP exceeded')
        
        if state.ckr is not None:
            while state.nr  < until:
                ck_step = kdf_ck(state.ckr)

                state.ckr = ck_step[0]
                mk = ck_step[1]
                state.nr += 1

                if state.dhr not in state.mkskipped.keys():
                    state.mkskipped[state.dhr] = {}
                # add key to dict
                state.mkskipped[state.dhr][state.nr] = mk
                state.nr +=  1
    
    @staticmethod
    def __dh_ratchet(state: DoubleRatchetState, header: DoubleRatchetHeader):
        '''
        Performs ratchet step to derive the relevant message key and next chain key.
        '''
        state.pn = state.ns
        state.ns = 0
        state.nr = 0
        state.dhr = header.dh
        kdf = DoubleRatchet.__kdf_rk(state.rk, DoubleRatchet.__dh(state.dhs, state.dhr))
        state.rk = kdf[0]
        state.ckr = kdf[1]
        state.dhs = DoubleRatchet.__generate_dh()
        kdf = DoubleRatchet.__kdf_rk(state.rk, DoubleRatchet.__dh(state.dhs, state.dhr))
        state.rk = kdf[0]
        state.cks = kdf[1]

    @staticmethod
    def __generate_dh() -> DoubleRatchetKeyPair:
        '''
        Generates pair of keys for DH.
        '''
        return DoubleRatchetKeyPairGenerator.generate_key_pair()
    
    @staticmethod
    def __dh(dh_pair: DoubleRatchetKeyPair, dh_pub: bytes) -> bytes:
        '''
        Calculates DH agreement.
        '''
        dh_pair.get_agreement(dh_pub)
    
    @staticmethod
    def __encrypt(mk: bytes, plaintext: bytes, ad: bytes) -> bytes:
        '''
        Encrypts plaintext using AES GCM block cipher.
        '''
        block_cipher = AES.new(key=mk, mode=AES.MODE_GCM, nonce=DoubleRatchet.fixed_nonce, mac_len=DoubleRatchet.mac_size)
        return block_cipher.encrypt(plaintext)
        
    @staticmethod
    def __decrypt(mk: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        '''
        Decrypts ciphertext using AES GCM block cipher.
        '''
        block_cipher = AES.new(mk, mode=AES.MODE_GCM, nonce=DoubleRatchet.fixed_nonce, mac_len=DoubleRatchet.mac_size)
        return block_cipher.decrypt(ciphertext)

    @staticmethod
    def __kdf_rk(rk: bytes, dh_out: bytes) -> (bytes, bytes):
        '''
        Performs key derivation using HKDF to obtain root key and chain key.
        '''
        ret = HKDF(dh_out, key_len=32, salt=rk, hashmod=SHA256, num_keys=1)
        return ret[:32], ret[32:]
        
    @staticmethod
    def __kdf_ck(ck: bytes) -> (bytes, bytes):
        '''
        Performs key derivation using HKDF to obtain chain key and message key.
        '''
        hmac = HMAC.new(ck, b'\x00'*64, SHA256)
        ret = hmac.hexdigest().encode()
        return ret[:32], ret[32:]