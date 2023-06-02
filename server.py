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
        self.msg_fmt = 0

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
            t1 = threading.Thread(target=self.handle,args=(sock,client_address))
            t1.start()


    def handle(self, sock,client_address):
        while True:
            try:
                length = sock.recv(4)
                total_length = struct.unpack(">I", length)[0]
                req_data = length + sock.recv(total_length - 4)
            except Exception as e:
                self.logger.warning(e)
                break
            command_id = struct.unpack(">I", req_data[4:8])[0]
            command_name = get_command_name(command_id)
            print(command_name)
            if command_name == "CMPP_CONNECT":
                self.cmpp_connect_resp(sock,req_data)
            elif command_name == "CMPP_TERMINATE":
                self.cmpp_terminate_resp(sock,req_data,client_address)
            elif command_name == "CMPP_SUBMIT":
                self.cmpp_submit_resp(sock,req_data)
            elif command_name == "CMPP_QUERY":
                self.cmpp_query_resp(sock,req_data)
            elif command_name == "CMPP_DELIVER_RESP":
                self.parse_cmpp_deliver_resp(req_data)
            elif command_name == "CMPP_CANCEL":
                self.cmpp_cancel_resp(sock,req_data)
            elif command_name == "CMPP_ACTIVE_TEST":
                self.cmpp_active_test_resp(sock,req_data)

    def base_send(self, command_name, sock, **kwargs):
        command_id = get_command_id(command_name)
        self.sequence_id += 1
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

    def cmpp_terminate_resp(self,sock,req_data,client_address):
        unpacked_data = self.base_parse("CMPP_TERMINATE", req_data)
        self.base_send("CMPP_TERMINATE_RESP", sock)
        time.sleep(1)
        self.logger.info(f"{client_address}断开连接")
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
        time.sleep(0.1)
        self.cmpp_deliver(sock,msg_bytes.decode())

    def cmpp_query_resp(self,sock, req_data):
        unpacked_data = self.base_parse("CMPP_QUERY", req_data)
        ti,query_type,query_code = unpacked_data[3:-1]
        body = {
            'time': ti.decode(),
            'query_type': query_type,
            'query_code': query_code.decode(),
            'mt_tl_msg': 3,  # 从SP接收信息总数
            'mt_tl_usr': 2,  # 从SP接收用户总数
            'mt_scs': 1,  # 成功转发数量
            'mt_wt': 1,  # 待转发数量
            'mt_fl': 1,  # 转发失败数量
            'mo_scs': 1,  # 向SP成功送达数量
            'mo_wt': 2,  # 向SP待送达数量
            'mo_fl': 3,  # 向SP送达失败数量
        }
        self.base_send("CMPP_QUERY_RESP", sock, **body)
        print("send success")

    def cmpp_deliver(self,sock,msg):
        body = {
            'msg_id': gen_msg_id(self.sequence_id),
            'dest_id': "18279230916",
            'service_id': config.SERVICE_ID,
            'tp_pid': 1,
            'tp_udhi': 1,
            'msg_fmt': self.msg_fmt,
            'src_terminal_id': "13520376620",
            'src_terminal_type': 0,
            'registered_delivery': 0,
            'msg_content': "recv:" + msg,
            'link_id': '',
        }
        self.base_send("CMPP_DELIVER",sock,**body)


    def parse_cmpp_deliver_resp(self,req_data):
        unpacked_data = self.base_parse("CMPP_DELIVER_RESP", req_data)
        msg_id,result = unpacked_data[3:]
        print(msg_id,result)

    def cmpp_cancel_resp(self,sock,req_data):
        unpacked_data = self.base_parse("CMPP_CANCEL", req_data)
        msg_id = unpacked_data[3]
        print(msg_id)
        self.base_send("CMPP_CANCEL_RESP",sock,success_id=0)

    def cmpp_active_test_resp(self,sock,req_data):
        unpacked_data = self.base_parse("CMPP_ACTIVE_TEST", req_data)
        print(unpacked_data)
        self.base_send("CMPP_ACTIVE_TEST_RESP", sock, reserved=' ')

    def CMPP_FWD(self,sock):
        body = {
            'source_id': '079210',
            'destination_id': '079220',
            'nodes_count': 5,
            'msg_fwd_type': Param(type=int, size=1),
            'msg_id': Param(type=int, size=8),
            'pk_total': Param(type=int, size=1),
            'pk_number': Param(type=int, size=1),
            'registered_delivery': Param(type=int, size=1),
            'msg_level': Param(type=int, size=1),
            'service_id': Param(type=str, size=10),
            'fee_usertype': Param(type=int, size=1),
            'fee_terminal_id': Param(type=str, size=21),
            'fee_terminal_pseudo': Param(type=str, size=32),
            'fee_terminal_usertype': Param(type=int, size=1),
            'tp_pid': Param(type=int, size=1),
            'tp_udhi': Param(type=int, size=1),
            'msg_fmt': Param(type=int, size=1),
            'msg_src': Param(type=str, size=6),
            'fee_type': Param(type=str, size=2),
            'fee_code': Param(type=str, size=6),
            'valid_time': Param(type=str, size=17),
            'at_time': Param(type=str, size=17),
            'src_id': Param(type=str, size=21),
            'src_pseudo': Param(type=str, size=32),
            'src_usertype': Param(type=int, size=1),
            'src_type': Param(type=int, size=1),
            'dest_usr_tl': Param(type=int, size=1),
            'dest_id': Param(type=str, size=21),
            'dest_pseudo': Param(type=str, size=32),
            'dest_usertype': Param(type=int, size=1),
            'msg_length': Param(type=int, size=1),
            'msg_content': Param(type=str),
            'link_id': Param(type=str, size=20),
        }
        self.base_send("CMPP_DELIVER", sock, **body)






if __name__ == '__main__':
    server = ISMG()
    server.start()
