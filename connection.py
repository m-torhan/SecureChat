import socket
import threading
import time
import datetime

import debug_tools

debug_tools.set_debug(True)

class Header(object):
    SIZE = 2
    def __init__(self, content_type, part_type):
        self.content_type = ContentType
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

class MessageType(object):
    INFO = 0
    SENT = 1
    RECEIVED = 2

class Message(object):
    def __init__(self, type, time, text):
        self.type = type
        self.time = time
        self.text = text

class Connection(object):
    def __init__(self, sock):
        self.__socket = sock

        self.__chat_history = []

        self.__send_queue = []

        def send_thread_fun():
            while True:
                time.sleep(.1)
                if len(self.__send_queue) > 0:
                    self.__send_data(*self.__send_queue.pop(0))
        
        def recv_thread_fun():
            while True:
                time.sleep(.1)
                content_type, data = self.__recv_data()

                if content_type == ContentType.MESSAGE:
                    self.__recv_message(data)
        
        self.__send_thread = threading.Thread(target=send_thread_fun)
        self.__recv_thread = threading.Thread(target=recv_thread_fun)

        self.__send_thread.start()
        self.__recv_thread.start()

    def send_message(self, text):
        self.__send_queue.append(ContentType.MESSAGE, text)

        self.__chat_history.append(Message(MessageType.SENT, datetime.datetime.now(), text))

    def __recv_message(self, text):
        self.__chat_history.append(Message(MessageType.RECEIVED, datetime.datetime.now(), text))
    
    def __send_data(self, content_type, data):
        if type(data) != bytes:
            encoded_data = data.encode('utf-8')
        else:
            encoded_data = data[:]

        packet_count = len(encoded_data)//PAYLOAD_SIZE + int((len(encoded_data)%PAYLOAD_SIZE) > 0)
        
        packets = []
        for i in range(packet_count):
            packet_part_type = 0
            if i == 0:
                packet_part_type |= PartType.FIRST
            if i == packet_count - 1:
                packet_part_type |= PartType.LAST
            if 0 < i < packet_count - 1:
                packet_part_type |= PartType.MIDDLE

            packet_payload = encoded_data[PAYLOAD_SIZE*i:min(PAYLOAD_SIZE*(i+1), len(encoded_data))]
            debug_tools.print_debug(packet_payload)
            packet_payload = packet_payload.ljust(PAYLOAD_SIZE, b'\x00')
            debug_tools.print_debug(len(packet_payload))

            packets.append(Packet(Header(content_type, packet_part_type), packet_payload))

        debug_tools.print_debug(len(packets))
        for packet in packets:
            debug_tools.print_debug(f'sending packet {packet} {len(packet.to_bytes())}')
            self.__socket.send(packet.to_bytes())

    def __recv_data(self):
        received_data = ''
        content_type = None

        while True:
            try:
                p = self.__socket.recv(PACKET_SIZE)
                debug_tools.print_debug(p.rstrip(b'\x00'))
                debug_tools.print_debug(len(p))
                packet = Packet.from_bytes(p)
                if content_type is None:
                    content_type = packet.header.content_type
                debug_tools.print_debug(f'received packet {packet}')
                received_data += packet.payload_str
                if packet.header.PartType & PartType.LAST:
                    break
            except:
                debug_tools.print_debug('ERROR')
                print('Connection lost')
                raise socket.timeout

        return content_type, received_data
    

PACKET_SIZE = 256
PAYLOAD_SIZE = PACKET_SIZE - Header.SIZE