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
        self.msg_id = None

        # Set up logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.command_mapping = {
                "CMPP_CONNECT": self.cmpp_connect_resp,
                "CMPP_TERMINATE": self.cmpp_terminate_resp,
                "CMPP_SUBMIT": self.cmpp_submit_resp,
                "CMPP_QUERY": self.cmpp_query_resp,
                "CMPP_DELIVER_RESP": self.parse_cmpp_deliver_resp,
                "CMPP_CANCEL": self.cmpp_cancel_resp,
                "CMPP_ACTIVE_TEST": self.cmpp_active_test_resp
            }

    def start(self):
        self.logger.info("server started!")
        while True:
            # 等待客户端连接
            sock, client_address = self.server_socket.accept()
            self.logger.info(f'Client connected:{client_address}')
            time.sleep(0.1)
            t1 = threading.Thread(target=self.handle, args=(sock,))
            t1.start()

    def handle(self, sock):
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
            self.logger.info(command_name)
            # noinspection PyArgumentList
            self.command_mapping.get(command_name, lambda *args: None)(command_name,sock, req_data)

    def base_send(self, command_name, sock, **kwargs):
        resp_command_name = command_name + "_RESP"
        command_id = get_command_id(resp_command_name)
        self.sequence_id += 1
        pdu = gen_pdu(resp_command_name)(command_id=command_id, sequence_id=self.sequence_id, **kwargs)
        data = pdu.pack()
        sock.sendall(data)

    def base_parse(self, command_name, req_data):
        header = {
            "total_length": None,
            "command_id": None,
            "sequence_id": None
        }
        pdu = gen_pdu(command_name)(**header)
        unpacked_data = pdu.unpack(req_data)
        self.sequence_id = unpacked_data[2]
        return unpacked_data

    def cmpp_connect_resp(self, command_name,sock, req_data):
        unpacked_data = self.base_parse(command_name, req_data)
        status = 0
        authenticator_source = unpacked_data[4]
        authenticator_ismg = gen_authenticator_ismg(status, authenticator_source)
        body = {
            "status": status,
            "authenticatorISMG": authenticator_ismg,
            "version": config.VERSION
        }
        self.base_send(command_name, sock, **body)

    def cmpp_terminate_resp(self, command_name,sock, req_data):
        unpacked_data = self.base_parse(command_name, req_data)
        self.base_send(command_name, sock)
        time.sleep(1)
        self.logger.info(f"客户端断开连接")

    def cmpp_submit_resp(self, command_name,sock, req_data):
        msg_bytes = req_data[175:-20]
        print("recv msg:", msg_bytes.decode())
        data = {
            "msg_bytes": msg_bytes
        }
        pdu = gen_pdu(command_name)(**data)
        unpacked_data = pdu.unpack(req_data)
        self.sequence_id = unpacked_data[2]
        self.msg_id = gen_msg_id(self.sequence_id)
        body = {
            "msg_id": self.msg_id,
            "result": 9,
        }
        self.base_send(command_name, sock, **body)
        time.sleep(0.1)
        self.cmpp_deliver(sock, msg_bytes.decode())

    def cmpp_query_resp(self, command_name,sock, req_data):
        unpacked_data = self.base_parse(command_name, req_data)
        ti, query_type, query_code = unpacked_data[3:-1]
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
        self.base_send(command_name, sock, **body)

    def cmpp_deliver(self, sock, msg):
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
        self.base_send("CMPP_DELIVER", sock, **body)

    def parse_cmpp_deliver_resp(self, command_name,sock, req_data):
        unpacked_data = self.base_parse(command_name, req_data)
        msg_id, result = unpacked_data[3:]
        print(msg_id, result)
        self.cmpp_mo_route(sock)
        time.sleep(0.1)
        self.cmpp_fwd(sock, str(msg_id))
        time.sleep(0.1)
        self.cmpp_mt_route(sock)
        time.sleep(0.1)
        self.cmpp_get_mt_route(sock)
        time.sleep(0.1)
        self.cmpp_get_mo_route(sock)
        time.sleep(0.1)
        self.cmpp_mt_route_update(sock)
        time.sleep(0.1)
        self.cmpp_mo_route_update(sock)
        time.sleep(0.1)
        self.cmpp_push_mt_route_update(sock)
        time.sleep(0.1)
        self.cmpp_push_mo_route_update(sock)

    def cmpp_cancel_resp(self, command_name,sock, req_data):
        unpacked_data = self.base_parse(command_name, req_data)
        msg_id = unpacked_data[3]
        print(msg_id)
        self.base_send(command_name, sock, success_id=0)

    def cmpp_active_test_resp(self, command_name,sock, req_data):
        unpacked_data = self.base_parse(command_name, req_data)
        print(unpacked_data)
        self.base_send(command_name, sock, reserved=' ')

    def cmpp_fwd(self, sock, msg):
        body = {
            'source_id': config.SOURCE_ID,
            'destination_id': config.DESTINATION_ID,
            'nodes_count': 5,
            'msg_fwd_type': 0,
            'msg_id': self.msg_id,
            'pk_total': 1,
            'pk_number': 1,
            'registered_delivery': 0,
            'msg_level': 1,
            'service_id': config.SERVICE_ID,
            'fee_usertype': 3,
            'fee_terminal_id': "13520376620",
            'fee_terminal_pseudo': " ",
            'fee_terminal_usertype': 0,
            'tp_pid': 1,
            'tp_udhi': 1,
            'msg_fmt': self.msg_fmt,
            'msg_src': config.SOURCE_ADDR,
            'fee_type': "03",
            'fee_code': "000001",
            'valid_time': "20230601120000",
            'at_time': "20230531155000",
            'src_id': "18279230916",
            'src_pseudo': " ",
            'src_usertype': 0,
            'src_type': 0,
            'dest_usr_tl': 1,
            'dest_id': "+8613520376620",
            'dest_pseudo': " ",
            'dest_usertype': 0,
            'msg_content': "cmpp fwd " + msg,
            'link_id': "",
        }
        self.base_send("CMPP_FWD", sock, **body)

    def cmpp_mt_route(self, sock):
        body = {
            "source_id": config.SOURCE_ID,
            "terminal_id": config.TERMINAL_ID
        }
        self.base_send("CMPP_MT_ROUTE", sock, **body)

    def cmpp_mo_route(self, sock):
        body = {
            "source_id": config.SOURCE_ID,
            "sp_code": config.SRC_ID,
            "service_id": config.SERVICE_ID,
            "service_code": 1234,
        }
        self.base_send("CMPP_MO_ROUTE", sock, **body)

    def cmpp_get_mt_route(self, sock):
        body = {
            "source_id": config.SOURCE_ID,
            "route_type": "MT",
            "last_route_id": -1,
        }
        self.base_send("CMPP_GET_MT_ROUTE", sock, **body)

    def cmpp_get_mo_route(self, sock):
        body = {
            "source_id": config.SOURCE_ID,
            "route_type": "MO",
            "last_route_id": -1,
        }
        self.base_send("CMPP_GET_MO_ROUTE", sock, **body)

    def cmpp_mt_route_update(self, sock):
        body = {
            "update_type": 2,
            "route_id": 1,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "start_id": "100000000",
            "end_id": "999999999",
            "area_code": "0792",
            "user_type": 0
        }
        self.base_send("CMPP_MT_ROUTE_UPDATE", sock, **body)

    def cmpp_mo_route_update(self, sock):
        body = {
            "update_type": 2,
            "route_id": 1,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "sp_id": config.SOURCE_ADDR,
            "sp_code": config.SRC_ID,
            "sp_acess_type": 0,
            "service_id": config.SERVICE_ID,
            "start_code": 1000,
            "end_code": 9999,
        }
        self.base_send("CMPP_MO_ROUTE_UPDATE", sock, **body)

    def cmpp_push_mt_route_update(self, sock):
        body = {
            "update_type": 2,
            "route_id": 1,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "start_id": "100000000",
            "end_id": "999999999",
            "area_code": "0792",
            "user_type": 0,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_PUSH_MT_ROUTE_UPDATE", sock, **body)

    def cmpp_push_mo_route_update(self, sock):
        body = {
            "update_type": 2,
            "route_id": 1,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "sp_id": config.SOURCE_ADDR,
            "sp_code": config.SRC_ID,
            "sp_acess_type": 0,
            "service_id": config.SERVICE_ID,
            "start_code": 1000,
            "end_code": 9999,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_PUSH_MO_ROUTE_UPDATE", sock, **body)


if __name__ == '__main__':
    server = ISMG()
    server.start()
