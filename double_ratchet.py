import curve25519
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import HMAC, SHA256

from debug_tools import *

class DoubleRatchetState(object):
    def __init__(self, dhs: bytes, dhr: bytes, rk: bytes, cks: bytes, ckr: bytes):
        self.dhs = dhs
        self.dhr = dhr
        self.rk = rk
        self.cks = cks
        self.ckr = ckr
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.mkskipped = {}

class DoubleRatchetHeader(object):
    def __init__(self, dh: bytes, pn: int, n: int):
        self.dh = dh
        self.pn = pn
        self.n =  n
    
    def to_bytes(self):
        return self.dh + int.to_bytes(self.pn, 4, byteorder='big') + int.to_bytes(self.n, 4, byteorder='big')
    
    @staticmethod
    def from_bytes(byte_array):
        return DoubleRatchetHeader(byte_array[:-8], int.from_bytes(byte_array[-8:-4], byteorder='big'), int.from_bytes(byte_array[-4:], byteorder='big'))
class DoubleRatchetPacket(object):
    def __init__(self, header:  DoubleRatchetHeader, payload: bytes):
        self.__header = header
        self.__payload = payload
    
    @property
    def header(self):
        return self.__header
        
    @property
    def payload(self):
        return self.__payload
    
    def to_bytes(self):
        return self.__header.to_bytes() + self.__payload
    
    @staticmethod
    def from_bytes(byte_array):
        print_debug('bytes to packet', type(byte_array), byte_array)
        return DoubleRatchetPacket(DoubleRatchetHeader.from_bytes(byte_array[:40]), byte_array[40:])

class DoubleRatchetKeyPair(object):
    def __init__(self, public_key: bytes, private_key: bytes):
        self.__public_key = public_key
        self.__private_key = private_key
    
    @property
    def public_key(self):
        return self.__public_key
        
    @property
    def private_key(self):
        return self.__private_key
    
    def get_agreement(self, public_key: bytes):
        return curve25519.calculateAgreement(public_key, self.__private_key)

class DoubleRatchetKeyPairGenerator(object):
    @staticmethod
    def generate_key_pair():
        r = get_random_bytes(32)
        return DoubleRatchetKeyPair(curve25519.generatePublicKey(r), curve25519.generatePrivateKey(r))

class DoubleRatchet(object):
    MAX_SKIP = 10
    app_specific_info = bytes(b'\x00')*32
    mac_size = 16
    fixed_nonce = b'\x24\x7b\x67\x10\x19\x75\x65\x41\x10\x2e'

    @staticmethod
    def create_initiator_state(sk: bytes, pk: bytes) -> DoubleRatchetState:
        key_pair = DoubleRatchetKeyPairGenerator.generate_key_pair()
        kdf_rk = DoubleRatchet.__kdf_rk(sk, DoubleRatchet.__dh(key_pair, pk))
        return DoubleRatchetState(key_pair, pk, *kdf_rk, None)
    
    @staticmethod
    def create_receiver_state(key_pair: DoubleRatchetKeyPair, sk: bytes) -> DoubleRatchetState:
        return DoubleRatchetState(key_pair, None, sk, None, None)
    
    @staticmethod
    def ratchet_encrypt(state: DoubleRatchetState, plaintext: str, ad: bytes) -> DoubleRatchetPacket:
        kdf = DoubleRatchet.__kdf_ck(state.cks)
        state.cks  = kdf[0]
        mk = kdf[1]
        header = DoubleRatchetHeader(state.dhs.public_key, state.pn, state.ns)
        state.ns +=  1
        print_debug(ad, type(ad), header.to_bytes(), type(header.to_bytes()))
        packet = DoubleRatchetPacket(header, DoubleRatchet.__encrypt(mk, plaintext.encode(), bytes(0)))
        return packet
    
    @staticmethod
    def ratchet_decrypt(state: DoubleRatchetState, packet: DoubleRatchetPacket, ad: bytes) -> bytes:
        plaintext = DoubleRatchet.__try_skipped_message_keys(state, packet, ad)
        if (plaintext != None):
            return plaintext
        elif state.dhr == None or packet.header.dh != state.dhr:
            DoubleRatchet.__skip_message_keys(state, packet.header.pn)
            DoubleRatchet.__dh_ratchet(state, packet.header)
        
        DoubleRatchet.__skip_message_keys(state, packet.header.n)
        kdf = DoubleRatchet.__kdf_ck(state.ckr)
        state.ckr = kdf[0]
        mk = kdf[1]
        state.nr += 1
        return DoubleRatchet.__decrypt(mk, packet.payload, ad + packet.header.to_bytes())

    @staticmethod
    def __try_skipped_message_keys(state: DoubleRatchetState, packet:  DoubleRatchetPacket, ad: bytes) -> bytes:
        if packet.header.dh not in state.mkskipped.keys():
            return None
        mk = state.mkskipped[packet.header.dh]
        if packet.header.n not in mk.keys():
            return None
        mk = mk[packet.header.n]
        del state.mkskipped[packet.header.dh][packet.header.n]
        return DoubleRatchet.__decrypt(mk, packet.payload, ad + packet.header.to_bytes())

    @staticmethod
    def __skip_message_keys(state: DoubleRatchetState, until: int):
        print_debug('skip', until, state.nr)
        if state.nr + DoubleRatchet.MAX_SKIP < until:
            print_debug('skip', until, state.nr, DoubleRatchet.MAX_SKIP)
            raise Exception('MAX_SKIP exceeded')
        
        if state.ckr is not None:
            while state.nr  < until:
                ck_step = kdf_ck(state.ckr)

                state.ckr = ck_step[0]
                mk = ck_step[1]
                state.nr += 1

                if state.dhr not in state.mkskipped.keys():
                    state.mkskipped[state.dhr] = {}
                state.mkskipped[state.dhr][state.nr] = mk
                state.nr +=  1
    
    @staticmethod
    def __dh_ratchet(state: DoubleRatchetState, header: DoubleRatchetHeader):
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
        return DoubleRatchetKeyPairGenerator.generate_key_pair()
    
    @staticmethod
    def __dh(dh_pair: DoubleRatchetKeyPair, dh_pub: bytes) -> bytes:
        dh_pair.get_agreement(dh_pub)
    
    @staticmethod
    def __encrypt(mk: bytes, plaintext: bytes, ad: bytes) -> bytes:
        print_debug(mk, type(mk))
        block_cipher = AES.new(key=mk, mode=AES.MODE_GCM, nonce=DoubleRatchet.fixed_nonce, mac_len=DoubleRatchet.mac_size)
        return block_cipher.encrypt(plaintext)
        
    @staticmethod
    def __decrypt(mk: bytes, ciphertext: bytes, ad: bytes) -> bytes:
        block_cipher = AES.new(mk, mode=AES.MODE_GCM, nonce=DoubleRatchet.fixed_nonce, mac_len=DoubleRatchet.mac_size)
        return block_cipher.decrypt(ciphertext)

    @staticmethod
    def __kdf_rk(rk: bytes, dh_out: bytes) -> (bytes, bytes):
        ret = HKDF(dh_out, key_len=32, salt=rk, hashmod=SHA256, num_keys=1)
        return ret[:32], ret[32:]
        
    @staticmethod
    def __kdf_ck(ck: bytes) -> (bytes, bytes):
        hmac = HMAC.new(ck, b'\x00'*64, SHA256)
        ret = hmac.hexdigest().encode()
        return ret[:32], ret[32:]

class User(object):
    def  __init__(self, name: str, dr_state: DoubleRatchetState, dr: DoubleRatchet):
        self.__name  = name
        self.__dr_state = dr_state
        self.__dr = dr
        self.log = []
    
    @property
    def name(self):
        return self.__name

    def send_message(self, other, message: str):
        packet = self.__dr.ratchet_encrypt(self.__dr_state, message, other.name.encode())
        self.__sendPacket(other, packet)

    def force_skip_message(self, other, message: str):
        return self.__dr.ratchet_encrypt(self.__dr_state, message, other.name.encode())

    def deliver_skipped_message(self, other, packet: DoubleRatchetPacket):
        self.__sendPacket(other, packet)
    
    def __on_message_received(self, other, message: str):
        self.log.append(message)
    
    def __sendPacket(self, other, packet: DoubleRatchetPacket):
        other.__on_packed_received(self, packet)
    
    def __on_packed_received(self, other, packet: DoubleRatchetPacket):
        message = self.__dr.ratchet_decrypt(self.__dr_state, packet, self.name.encode()).decode()
        self.__on_message_received(other, message)