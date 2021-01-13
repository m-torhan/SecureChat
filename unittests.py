import unittest

from time import sleep
import socket
from connection import *


class ConnectionTest(unittest.TestCase):
    def test_connect(self):
        hostname, port = '192.168.0.10', 5757

        listener = Listener(hostname, port)
        connection_1 = Connection.connect(hostname, port)

        sleep(.1)
        
        self.assertEqual(len(listener.connections), 1)
        
        connection_2 = Connection.connect(hostname, port)

        sleep(.1)
        
        self.assertEqual(len(listener.connections), 2)

        connection_1.close()
        connection_2.close()
        listener.connections[0].close()
        listener.close()
    
    def test_send_message(self):
        hostname, port = '192.168.0.10', 5757

        listener = Listener(hostname, port)
        connection_1 = Connection.connect(hostname, port)

        connection_1.send_message('test message')

        sleep(.5)

        connection_2 = listener.connections.pop()

        self.assertEqual(len(connection_1.chat_history), 1)

        self.assertEqual(len(connection_2.chat_history), 1)
        
        connection_1.close()
        connection_2.close()
        listener.close()


if __name__ == '__main__':
    unittest.main()