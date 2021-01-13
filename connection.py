import socket
import threading
import time
import datetime

import debug_tools

debug_tools.set_debug(True)

# packet header 
class Header(object):
    SIZE = 2
    def __init__(self, content_type, part_type):
        self.content_type = content_type
        self.part_type = part_type

    def to_bytes(self):
        return bytes((self.content_type, self.part_type))
    
    @staticmethod
    def from_bytes(byte_array):
        assert len(byte_array) == 2, 'Wrong length of byte array'
        return Header(byte_array[0], byte_array[1])
    
    def __repr__(self):
        return f'Header({self.content_type}, {self.part_type})'

class ContentType(object):
    MESSAGE =   0x01

class PartType(object):
    FIRST =     0x01
    MIDDLE =    0x02
    LAST =      0x04

class Packet(object):
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

    def __getattr__(self, name):
        if name == 'payload_str':
            return self.payload.rstrip(b'\x00').decode('utf-8', 'replace')

    def to_bytes(self):
        return self.header.to_bytes() + self.payload

    @staticmethod
    def from_bytes(byte_array):
        assert len(byte_array) == PACKET_SIZE, 'Wrong length of byte array'
        return Packet(Header.from_bytes(byte_array[:2]), byte_array[2:].ljust(PAYLOAD_SIZE, b'\x00'))
                      
    def __repr__(self):
        return f'Packet({self.header}, {self.payload_str})'

class MessageFlag(object):
    INFO =      0x01
    SENT =      0x02
    RECEIVED =  0x04
    DELIVERED = 0x08

class Message(object):
    def __init__(self, message_type, time, text):
        self.type = message_type
        self.time = time
        self.text = text

class Listener(object):
    def __init__(self, hostname, port=None):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if port is None:
            port = 10000
            while True:
                try:
                    self.__socket.bind((hostname, port))
                    break
                except socket.error:
                    port += 1
        else:
            self.__socket.bind((hostname, port))

        self.__socket.listen(1)

        self.connections = []

        self.__run = True

        def listener_thread_fun():
            while self.__run:
                try:
                    sock, address = self.__socket.accept()
                    self.connections.append(Connection(sock))
                except:
                    break

        self.__listener_thread = threading.Thread(target=listener_thread_fun)
        self.__listener_thread.start()

    @property
    def address(self):
        return self.__socket.getsockname()

    def close(self):
        self.__run = False
        self.__socket.close()
        self.__listener_thread.join()

class Connection(object):
    def __init__(self, socket, remote_address=None):
        self.__socket = socket

        if remote_address is None:
            self.remote_address = self.__socket.getsockname()
        else:
            self.remote_address = remote_address

        self.closed = False
        self.close_handled = False

        self.chat_history = []

        self.__send_queue = []

        self.__run = True
        def send_thread_fun():
            while self.__run:
                time.sleep(.1)
                if len(self.__send_queue) > 0:
                    self.__send_data(*self.__send_queue.pop(0))
        
        def recv_thread_fun():
            while self.__run:
                time.sleep(.1)
                try:
                    content_type, data = self.__recv_data()
                except TimeoutError:
                    break

                if content_type == ContentType.MESSAGE:
                    self.__recv_message(data)
                
        self.__send_thread = threading.Thread(target=send_thread_fun)
        self.__recv_thread = threading.Thread(target=recv_thread_fun)

        self.__send_thread.start()
        self.__recv_thread.start()

    def send_message(self, text):
        self.chat_history.append(Message(MessageFlag.SENT, datetime.datetime.now(), text))
        if self.closed:
            self.chat_history.append(Message(MessageFlag.INFO, datetime.datetime.now(), 'Cannot send message. Connection is closed'))
            return

        self.__send_queue.append((ContentType.MESSAGE, text))
    
    def close(self):
        self.__run = False
        self.__send_thread.join()
        self.__socket.close()
        self.__recv_thread.join()
        self.closed = True

    @classmethod
    def connect(cls, hostname, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        return Connection(sock, (hostname, port))

    def __recv_message(self, text):
        self.chat_history.append(Message(MessageFlag.RECEIVED, datetime.datetime.now(), text))
    
    def __send_data(self, content_type, data):
        if type(data) != bytes:
            encoded_data = data.encode('utf-8')
        else:
            encoded_data = data[:]

        # calculate packets count
        packet_count = len(encoded_data)//PAYLOAD_SIZE + int((len(encoded_data)%PAYLOAD_SIZE) > 0)
        
        # create packets
        packets = []
        for i in range(packet_count):
            packet_part_type = 0
            # specify part type
            if i == 0:
                packet_part_type |= PartType.FIRST
            if i == packet_count - 1:
                packet_part_type |= PartType.LAST
            if 0 < i < packet_count - 1:
                packet_part_type |= PartType.MIDDLE

            # set packet payload
            packet_payload = encoded_data[PAYLOAD_SIZE*i:min(PAYLOAD_SIZE*(i+1), len(encoded_data))]
            debug_tools.print_debug(packet_payload)
            # fill with zeros
            packet_payload = packet_payload.ljust(PAYLOAD_SIZE, b'\x00')
            debug_tools.print_debug(len(packet_payload))

            packets.append(Packet(Header(content_type, packet_part_type), packet_payload))

        debug_tools.print_debug(len(packets))
        # send all packets
        for packet in packets:
            debug_tools.print_debug(f'sending packet {packet} {len(packet.to_bytes())}')
            self.__socket.send(packet.to_bytes())

    def __recv_data(self):
        received_data = ''
        content_type = None

        while True:
            try:
                # receive bytes
                packet_bytes = self.__socket.recv(PACKET_SIZE)
                debug_tools.print_debug(packet_bytes.rstrip(b'\x00'))
                debug_tools.print_debug(len(packet_bytes))
                # parse bytes to packet
                packet = Packet.from_bytes(packet_bytes)
                if content_type is None:
                    content_type = packet.header.content_type
                debug_tools.print_debug(f'received packet {packet}')
                received_data += packet.payload_str
                # break if received packet is last
                if packet.header.part_type & PartType.LAST:
                    break
            except:
                debug_tools.print_debug('ERROR')
                print('Connection lost')
                self.closed = True
                raise TimeoutError

        return content_type, received_data    

PACKET_SIZE = 256
PAYLOAD_SIZE = PACKET_SIZE - Header.SIZE