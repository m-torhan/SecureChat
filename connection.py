from __future__ import annotations
import socket
import threading
import time
import datetime

from double_ratchet import *

class ContentType(object):
    '''
    Enum that specifies Packet content.
    '''
    MESSAGE =               0x01
    DOUBLE_RATCHET_PACKET = 0x02
    PUBLIC_KEY =            0x04

class PartType(object):
    '''
    Enum that specifies Packet type.
    '''
    FIRST =     0x01
    MIDDLE =    0x02
    LAST =      0x04
class Header(object):
    '''
    Header class that contains information about packet's content.
    '''
    SIZE = 2
    def __init__(self, content_type: ContentType, part_type: PartType =PartType.FIRST | PartType.LAST) -> Header:
        '''
        Header constructor.       
        '''
        self.content_type = content_type
        self.part_type = part_type

    def to_bytes(self) -> bytes:
        '''
        Converts Header to byte array.
        '''
        return bytes((self.content_type, self.part_type))
    
    @staticmethod
    def from_bytes(byte_array: bytes) -> Header:
        '''
        Converts byte array to Header.
        '''
        assert len(byte_array) == Header.SIZE, 'Wrong length of byte array'
        return Header(byte_array[0], byte_array[1])
    
    def __repr__(self) -> str:
        '''
        Returns string representation of Header.
        '''
        return f'Header({self.content_type}, {self.part_type})'

class Packet(object):
    '''
    Packet class that represent portion of data.
    '''
    def __init__(self, header: Header, payload: bytes) -> Packet:
        '''
        Packet constructor.
        '''
        self.header = header
        self.payload = payload

    @property
    def payload_str(self) -> str:
        '''
        Getter that returns payload converted to string.
        '''
        return self.payload.rstrip(b'\x00').decode('utf-8', 'replace')

    def to_bytes(self) -> bytes:
        '''
        Converts Packet to byte array.
        '''
        return self.header.to_bytes() + self.payload

    @staticmethod
    def from_bytes(byte_array: bytes) -> Packet:
        '''
        Converts byte array to Packet.
        '''
        assert len(byte_array) == PACKET_SIZE, 'Wrong length of byte array'
        return Packet(Header.from_bytes(byte_array[:2]), byte_array[2:].ljust(PAYLOAD_SIZE, b'\x00'))
                      
    def __repr__(self) -> str:
        '''
        Returns string representation of Packet.
        '''
        p = self.payload.rstrip(b'\x00')
        return f'Packet({self.header}, {p})'

class MessageFlag(object):
    '''
    Enum that specifies message type.
    '''
    INFO =      0x01
    SENT =      0x02
    RECEIVED =  0x04

class Message(object):
    '''
    Message class that represents chat message.
    '''
    def __init__(self, message_type: MessageFlag, time: datetime.datetime, text: str):
        '''
        Message constructor.
        '''
        self.type = message_type
        self.time = time
        self.text = text

class Listener(object):
    '''
    Listener class that handles incoming connections.
    '''
    def __init__(self, hostname: str, port:int = None) -> Listener:
        '''
        Listener constructor.
        '''
        # create socket for listening
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if port is None:
            # look for available port if it is not specified
            port = 10000
            while True:
                try:
                    self.__socket.bind((hostname, port))
                    # bind successfull - port is OK
                    break
                except socket.error:
                    port += 1
        else:
            # bind using specified port
            self.__socket.bind((hostname, port))

        # start listening
        self.__socket.listen(1)

        self.connections = []

        self.__run = True

        def listener_thread_fun():
            # function for incoming connections handling that is target of another thread
            while self.__run:
                try:
                    # wait for connection
                    sock, address = self.__socket.accept()
                    # add new connection to list
                    self.connections.append(Connection(sock, local_address=address))
                except:
                    break
        
        # start listening thread
        self.__listener_thread = threading.Thread(target=listener_thread_fun)
        self.__listener_thread.start()

    @property
    def address(self) -> tuple(str, int):
        '''
        Returns Listener's address.
        '''
        return self.__socket.getsockname()

    def close(self):
        '''
        Closes listening.
        '''
        # stop thread and join it
        self.__socket.close()
        self.__listener_thread.join()
        self.__run = False

class Connection(object):
    '''
    Connection class that handles sockets, data exchange, encryption and decrypption.
    '''
    def __init__(self, socket: socket.socket, local_address: tuple(str, int) =None, remote_address: tuple(str, int) =None) -> Connection:
        '''
        Connection constructor.
        '''
        self.__socket = socket

        # determine if this connections is the initiator (used in double ratchet algorithm init)
        self.__initiator = remote_address is not None

        # set local and remote addresses
        if remote_address is None:
            self.local_address = local_address
            self.remote_address = self.__socket.getsockname()
        else:
            self.local_address = self.__socket.getsockname()
            self.remote_address = remote_address

        self.closed = False
        self.close_handled = False

        self.chat_history = []

        self.__send_queue = []

        self.__run = True

        def send_thread_fun():
            # send all packets awaiting in queue
            while self.__run:
                time.sleep(.1)
                if len(self.__send_queue) > 0:
                    self.__send_data(self.__send_queue.pop(0))
        
        def recv_thread_fun():
            # receive packets and place them in queue
            while self.__run:
                time.sleep(.1)
                try:
                    packet = self.__recv_data()
                except TimeoutError:
                    break
                
                # handle data based on its content type
                if packet.header.content_type == ContentType.MESSAGE:
                    self.__recv_message(packet.payload, decrypt=False)
                elif packet.header.content_type == ContentType.DOUBLE_RATCHET_PACKET:
                    self.__recv_message(packet.payload, decrypt=True)
                elif packet.header.content_type == ContentType.PUBLIC_KEY:
                    received_public_key = packet.payload[:32]
                    sk = self.__key_pair.get_agreement(received_public_key)
                    if self.__dr_state is None:
                        # initialize double ratchet state
                        if self.__initiator:
                            self.__dr_state = self.__dr.create_initiator_state(sk, self.__key_pair.public_key)
                        else:
                            self.__dr_state = self.__dr.create_receiver_state(self.__key_pair, sk)
                
        self.__send_thread = threading.Thread(target=send_thread_fun)
        self.__recv_thread = threading.Thread(target=recv_thread_fun)

        # generate key pair and initialize double ratchet
        self.__key_pair = DoubleRatchetKeyPairGenerator.generate_key_pair()
        self.__dr = DoubleRatchet()
        self.__dr_state = None

        # send public key
        self.__send_queue.append(Packet(Header(ContentType.PUBLIC_KEY), self.__key_pair.public_key))

        # start send and receive threads
        self.__send_thread.start()
        self.__recv_thread.start()

    def send_message(self, text: str, encrypt: bool =True):
        '''
        Handles message sending.
        '''
        # add message to chat history
        self.chat_history.append(Message(MessageFlag.SENT, datetime.datetime.now(), text))

        if self.closed:
            # if connection is closed then message can not be send
            self.chat_history.append(Message(MessageFlag.INFO, datetime.datetime.now(), 'Cannot send message. Connection is closed'))
            return
        if encrypt:
            # encrypt message before sending
            if self.__dr_state is not None:
                self.__send_queue.append(Packet(Header(ContentType.DOUBLE_RATCHET_PACKET), self.__dr.ratchet_encrypt(self.__dr_state, text, self.remote_address)))
            else:
                self.chat_history.append(Message(MessageFlag.INFO, datetime.datetime.now(), 'Cannot send message. Encryption error'))
        else:
            # just send plaintext
            self.__send_queue.append(Packet(Header(ContentType.MESSAGE), text))
    
    def close(self):
        '''
        Closes connection.
        '''
        # stop threads and join them
        self.__run = False
        self.__send_thread.join()
        self.__socket.close()
        self.__recv_thread.join()
        self.closed = True

    @classmethod
    def connect(cls, hostname: str, port: int):
        '''
        Creates connection and connects it to specified host
        '''
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname, port))
        return Connection(sock, remote_address=(hostname, port))

    def __recv_message(self, text: str, decrypt: bool =True):
        '''
        Handles received message.
        '''
        if decrypt:
            # decrypt it if its encrypted
            text = self.__dr.ratchet_decrypt(self.__dr_state, DoubleRatchetPacket.from_bytes(text.rstrip(b'\x00')), self.local_address[0].encode())
            text = text.decode('utf-8')
        
        # add it to chat history
        self.chat_history.append(Message(MessageFlag.RECEIVED, datetime.datetime.now(), text))
    
    def __send_data(self, packet: Packet):
        '''
        Handles data sending.
        '''
        if packet.header.content_type == ContentType.MESSAGE:
            # if its message convert it to bytes if needed
            if type(packet.payload) != bytes:
                encoded_data = packet.payload.encode('utf-8')
            else:
                encoded_data = packet.payload[:]
        elif packet.header.content_type == ContentType.DOUBLE_RATCHET_PACKET:
            # if its double ratchet packet - convert it to bytes
            encoded_data = packet.payload.to_bytes()
        else:
            encoded_data = packet.payload[:]

        # big packets should be splitted to smaller ones

        # calculate smaller packets count
        packet_count = len(encoded_data)//PAYLOAD_SIZE + int((len(encoded_data)%PAYLOAD_SIZE) > 0)
        
        # create smaller packets
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
            # fill with zeros
            packet_payload = packet_payload.ljust(PAYLOAD_SIZE, b'\x00')

            packets.append(Packet(Header(packet.header.content_type, packet_part_type), packet_payload))

        # send all packets
        for packet in packets:
            self.__socket.send(packet.to_bytes())

    def __recv_data(self):
        '''
        Handles received packets.
        '''
        received_data = ''
        content_type = None

        while True:
            try:
                # receive bytes
                packet_bytes = self.__socket.recv(PACKET_SIZE)
                # parse bytes to packet
                packet = Packet.from_bytes(packet_bytes)
                if content_type is None:
                    content_type = packet.header.content_type
                
                # concatenate received data
                if content_type == ContentType.MESSAGE:
                    # strings
                    received_data += packet.payload_str
                else:
                    # bytes
                    if received_data == '':
                        received_data = b''
                    received_data += packet.payload
                # break if received packet is last
                if packet.header.part_type & PartType.LAST:
                    break
            except:
                self.closed = True
                raise TimeoutError

        return Packet(Header(content_type), received_data)

# constant values
PACKET_SIZE = 256                           # size of exchanged packets
PAYLOAD_SIZE = PACKET_SIZE - Header.SIZE    # size of packet payload