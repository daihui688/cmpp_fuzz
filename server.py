import logging
import socket
import threading
import time

from command import get_command_id, get_command_name
from utils import *


class ISMG:
    def __init__(self, host=config.ISMG_HOST, port=config.ISMG_PORT):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.sequence_id = None

        # Set up logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def start(self):
        self.logger.info("server started!")
        while True:
            # 等待客户端连接
            sock, client_address = self.server_socket.accept()
            self.logger.info(f'Client connected:{client_address}')
            time.sleep(0.1)
            t2 = threading.Thread(target=self.handle,args=(sock,))
            t2.start()


    def handle(self, sock):
        while True:
            try:
                length = sock.recv(4)
            except Exception as e:
                self.logger.warning(e)
                break
            total_length = struct.unpack(">I", length)[0]
            req_data = length + sock.recv(total_length - 4)
            command_id = struct.unpack(">I", req_data[4:8])[0]
            command_name = get_command_name(command_id)
            print(command_name)
            if command_name == "CMPP_CONNECT":
                self.cmpp_connect_resp(sock,req_data)
            elif command_name == "CMPP_TERMINATE":
                self.cmpp_terminate_resp(sock)
            elif command_name == "CMPP_SUBMIT":
                self.cmpp_submit_resp(sock,req_data)
            elif command_name == "CMPP_QUERY":
                self.cmpp_query_resp(sock,req_data)

    def base_send(self, command_name, sock, **kwargs):
        command_id = get_command_id(command_name)
        pdu = gen_pdu(command_name)(command_id=command_id, sequence_id=self.sequence_id, **kwargs)
        data = pdu.pack()
        sock.sendall(data)
    def base_parse(self,command_name,req_data):
        header = {
            "total_length": None,
            "command_id": None,
            "sequence_id": None
        }
        pdu = gen_pdu(command_name)(**header)
        unpacked_data = pdu.unpack(req_data)
        self.sequence_id = unpacked_data[2]
        return unpacked_data

    def cmpp_connect_resp(self, sock,req_data):
        unpacked_data = self.base_parse("CMPP_CONNECT",req_data)
        status = 0
        authenticator_source = unpacked_data[4]
        authenticator_ismg = gen_authenticator_ismg(status, authenticator_source)
        body = {
            "status": status,
            "authenticatorISMG": authenticator_ismg,
            "version": config.VERSION
        }
        self.base_send("CMPP_CONNECT_RESP", sock, **body)

    def cmpp_terminate_resp(self,sock):
        self.base_send("CMPP_TERMINATE_RESP", sock)
    def cmpp_submit_resp(self, sock, req_data):
        msg_bytes = req_data[175:-20]
        print("recv msg:",msg_bytes.decode())
        data = {
            "msg_bytes":msg_bytes
        }
        pdu = gen_pdu("CMPP_SUBMIT")(**data)
        unpacked_data = pdu.unpack(req_data)
        self.sequence_id = unpacked_data[2]
        body = {
            "msg_id": gen_msg_id(self.sequence_id),
            "result": 9,
        }
        self.base_send("CMPP_SUBMIT_RESP", sock, **body)

    def cmpp_query_resp(self,sock, req_data):
        pass


if __name__ == '__main__':
    server = ISMG()
    server.start()
