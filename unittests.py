import unittest

from time import sleep

from connection import *
from double_ratchet import *

class User(object):
    '''
    Just for test purpose.
    '''
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

class ConnectionTest(unittest.TestCase):
    def test_connect(self):
        hostname, port = '192.168.0.10', 5757

        listener = Listener(hostname, port)
        connection_1 = Connection.connect(hostname, port)

        sleep(.1)
        
        self.assertEqual(len(listener.connections), 1)
        
        connection_2 = Connection.connect(hostname, port)

        sleep(.5)
        
        self.assertEqual(len(listener.connections), 2)

        connection_1.close()
        listener.connections[0].close()
        connection_2.close()
        listener.connections[1].close()
        listener.close()
    
    def test_send_message(self):
        hostname, port = '192.168.0.10', 5757

        listener = Listener(hostname, port)
        connection_1 = Connection.connect(hostname, port)

        sleep(.5)

        connection_1.send_message('test message', encrypt=False)

        sleep(.5)

        connection_2 = listener.connections.pop()

        self.assertEqual(len(connection_1.chat_history), 1)

        self.assertEqual(len(connection_2.chat_history), 1)
        
        connection_1.close()
        connection_2.close()
        listener.close()

class DoubleRatchetTest(unittest.TestCase):
    def test_dr(self):
        dr = DoubleRatchet()

        key_pair_alice = DoubleRatchetKeyPairGenerator.generate_key_pair()
        key_pair_bob = DoubleRatchetKeyPairGenerator.generate_key_pair()

        sk_bob = key_pair_bob.get_agreement(key_pair_alice.public_key)
        sk_alice = key_pair_alice.get_agreement(key_pair_bob.public_key)

        bob = User(
            'Bob',
            dr.create_receiver_state(key_pair_bob, sk_bob),
            dr)
        
        alice = User(
            'Alice',
            dr.create_initiator_state(sk_alice, key_pair_bob.public_key),
            dr)
        
        alice.send_message(bob, 'test')
        self.assertEqual(bob.log[0], 'test')

        alice.send_message(bob, 'test2')
        self.assertEqual(bob.log[1], 'test2')

        bob.send_message(alice, 'test3')
        self.assertEqual(alice.log[0], 'test3')

class SecureConnectionTest(unittest.TestCase):
    def test_send_message(self):
        hostname, port = '192.168.0.10', 5757

        listener = Listener(hostname, port)
        connection_1 = Connection.connect(hostname, port)

        sleep(.5)

        connection_1.send_message('test message', encrypt=True)

        sleep(.5)

        connection_2 = listener.connections.pop()

        self.assertEqual(len(connection_1.chat_history), 1)
        self.assertEqual(connection_1.chat_history[0].text, 'test message')

        self.assertEqual(len(connection_2.chat_history), 1)
        self.assertEqual(connection_2.chat_history[0].text, 'test message')

        connection_2.send_message('test message 2', encrypt=True)

        sleep(.5)

        self.assertEqual(len(connection_1.chat_history), 2)
        self.assertEqual(connection_1.chat_history[1].text, 'test message 2')

        self.assertEqual(len(connection_2.chat_history), 2)
        self.assertEqual(connection_2.chat_history[1].text, 'test message 2')
        
        connection_1.close()
        connection_2.close()
        listener.close()

if __name__ == '__main__':
    unittest.main(exit=False)