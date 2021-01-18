import unittest

from time import sleep
import socket
from connection import *
from double_ratchet import *

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

        connection_1.send_message('test message')

        sleep(.5)

        connection_2 = listener.connections.pop()

        self.assertEqual(len(connection_1.chat_history), 1)

        self.assertEqual(len(connection_2.chat_history), 1)
        
        connection_1.close()
        connection_2.close()
        listener.close()

class DoubleRatchetTest(unittest.TestCase):
    def test_1(self):
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


if __name__ == '__main__':
    unittest.main()