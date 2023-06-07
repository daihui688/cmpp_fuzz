import logging
import socket
import threading
import time

from command import get_command_id, get_command_name
from fuzz import fuzzer
from utils import *


class SP:
    def __init__(self, host):
        self.host = host
        self.client = None
        self.sequence_id = 0
        self.connect_ismg = False
        self.msg_fmt = 0
        self.last_msg_id = None
        self.fuzz_num = 1
        self.handle_num = 0

        # Set up logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        self.command_mapping = {
                "CMPP_CONNECT_RESP": self.parse_cmpp_connect_resp,
                "CMPP_TERMINATE_RESP": self.parse_cmpp_terminate_resp,
                "CMPP_SUBMIT_RESP": self.parse_cmpp_submit_resp,
                "CMPP_DELIVER": self.parse_cmpp_deliver,
                "CMPP_QUERY_RESP": self.parse_cmpp_query_resp,
                "CMPP_ACTIVE_TEST_RESP": self.parse_cmpp_active_test_resp,
                "CMPP_CANCEL_RESP": self.parse_cmpp_cancel_resp,
                "CMPP_FWD": self.parse_cmpp_fwd,
                "CMPP_MT_ROUTE": self.cmpp_mt_route_resp,
                "CMPP_MO_ROUTE": self.cmpp_mo_route_resp,
                "CMPP_GET_MT_ROUTE": self.cmpp_get_mt_route_resp,
                "CMPP_GET_MO_ROUTE": self.cmpp_get_mo_route_resp,
                "CMPP_MT_ROUTE_UPDATE": self.cmpp_mt_route_update_resp,
                "CMPP_MO_ROUTE_UPDATE": self.cmpp_mo_route_update_resp,
                "CMPP_PUSH_MT_ROUTE_UPDATE": self.cmpp_push_mt_route_update_resp,
                "CMPP_PUSH_MO_ROUTE_UPDATE": self.cmpp_push_mo_route_update_resp
            }

    def connect(self, host=config.ISMG_HOST, port=config.ISMG_PORT):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 客户端绑定到self.host,0表示让系统自动选择一个可用的空闲端口
        self.client.bind((self.host, 0))
        try:
            self.client.connect((host, port))
        except Exception as e:
            self.logger.error(f"连接到{host}:{port}失败,{e}")
        else:
            self.logger.info(f"{self.client.getsockname()}连接到{host}:{port}")

    def disconnect(self):
        if self.client:
            self.logger.warning(f"SP{self.client.getsockname()}断开连接")
            self.client.close()

    def run(self, count, loop, interval):
        """
        :param count: 发送数量
        :param loop: 循环次数
        :param interval: 发送间隔
        """
        t1 = threading.Thread(target=self.handle)
        t1.start()
        self.cmpp_connect()
        t2 = threading.Thread(target=self.active_test)
        t2.start()
        for i in range(loop):
            # option = input("请输入你要执行的操作编号(0.测试,1.发送消息):")
            option = "1"
            if option == "0":
                self.cmpp_query()
                time.sleep(interval)
                self.cmpp_cancel(self.last_msg_id)
                time.sleep(interval)
            elif option == "1":
                for i in range(count):
                    # msg = input("请输入你要发送的消息:")
                    msg = "daihui688"
                    if contains_chinese(msg):
                        self.msg_fmt = 8
                    if msg.strip().upper() == "Q":
                        self.cmpp_terminate()
                        break
                    self.cmpp_submit(msg)
                    time.sleep(interval)
            elif option == "q":
                self.cmpp_terminate()
                break
            else:
                self.logger.error("错误的编号!")

    def handle(self):
        while True:
            if self.handle_num > 1 and not self.connect_ismg:
                self.logger.warning("handle() exit!")
                break
            length = self.client.recv(4)
            command_length = struct.unpack(">I", length)[0]
            resp = length + self.client.recv(command_length - 4)
            command_id = struct.unpack(">L", resp[4:8])[0]
            command_name = get_command_name(command_id)
            if command_name in self.command_mapping:
                if command_name == "CMPP_CONNECT_RESP":
                    self.parse_cmpp_connect_resp(resp, command_name)
                    self.handle_num = 1
                else:
                    # noinspection PyArgumentList
                    self.command_mapping.get(command_name, lambda: None)(resp, command_name)
            else:
                self.logger.error("异常数据")
                with open(f"./data/err_resp_data/{self.fuzz_num}", "wb") as f:
                    f.write(resp)

    def active_test(self):
        while True:
            if not self.connect_ismg:
                break
            try:
                time.sleep(60)
                self.cmpp_active_test()
            except Exception as e:
                self.logger.error(e)
                break

    def base_send(self, command_name, **kwargs):
        command_id = get_command_id(command_name)
        self.sequence_id += 1
        pdu = gen_pdu(command_name)(command_id=command_id, sequence_id=self.sequence_id, **kwargs)
        data = pdu.pack()
        self.client.sendall(data)

    @staticmethod
    def parse_base_resp(resp, command_name):
        header = {
            "total_length": None,
            "command_id": None,
            "sequence_id": None
        }
        pdu = gen_pdu(command_name)(**header)
        resp_data = pdu.unpack(resp)
        pdu.total_length, pdu.command_id, pdu.sequence_id = resp_data
        return pdu

    def cmpp_connect(self):
        timestamp = gen_timestamp()
        authenticator_source = gen_authenticator_source()
        body = {
            'source_addr': config.SOURCE_ADDR,
            'authenticator_source': authenticator_source,
            'version': config.VERSION,
            'timestamp': timestamp,
        }
        self.base_send("CMPP_CONNECT", **body)

    def parse_cmpp_connect_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        resp_data = pdu.unpack(resp)
        pdu.total_length, pdu.command_id, pdu.sequence_id, pdu.status, pdu.authenticatorISMG, pdu.version = resp_data
        if pdu.status == 0:
            self.logger.info(f"与ISMG连接成功,{pdu}")
            self.connect_ismg = True

    def cmpp_terminate(self):
        self.base_send("CMPP_TERMINATE")

    def parse_cmpp_terminate_resp(self, resp, command_name):
        pdu = self.parse_base_resp(resp, command_name)
        print(pdu.sequence_id, self.sequence_id)
        if pdu.sequence_id == self.sequence_id:
            self.logger.info(f"断开连接,{pdu}")
            self.connect_ismg = False
            self.disconnect()

    def cmpp_submit(self, msg):
        body = {
            'msg_id': 0,
            'pk_total': 1,
            'pk_number': 1,
            'registered_delivery': 1,
            'msg_level': 2,
            'service_id': config.SERVICE_ID,
            'fee_usertype': 3,
            'fee_terminal_id': config.SRC_ID,
            'fee_terminal_type': 0,
            'tp_pid': 1,
            'tp_udhi': 1,
            'msg_fmt': self.msg_fmt,
            'msg_src': config.SOURCE_ADDR,
            'fee_type': "02",
            'fee_code': "000001",
            'valid_time': "20230601120000",
            'at_time': "20230531155000",
            'src_id': config.SRC_ID,
            'dest_usr_tl': 1,
            'dest_terminal_id': config.TERMINAL_ID,
            'dest_terminal_type': 0,
            'msg_content': msg,
            'link_id': "",
        }
        self.base_send("CMPP_SUBMIT", **body)

    def parse_cmpp_submit_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        resp_data = pdu.unpack(resp)
        pdu.total_length, pdu.command_id, pdu.sequence_id, pdu.msg_id, pdu.result = resp_data
        if pdu.sequence_id == self.sequence_id:
            self.logger.info(f"发送消息成功,{pdu}")
            self.last_msg_id = pdu.msg_id

    def parse_cmpp_deliver(self, data, command_name):
        msg = data[89:-20]
        print("收到ISMG投递消息：", msg.decode())
        pdu = gen_pdu(command_name)(msg_content=msg.decode())
        unpack_data = pdu.unpack(data)
        pdu.msg_id = unpack_data[3]
        self.cmpp_deliver_resp(pdu.msg_id)

    def cmpp_deliver_resp(self, msg_id):
        body = {
            "msg_id": msg_id,
            "result": 0,
        }
        self.base_send("CMPP_DELIVER_RESP", **body)

    def cmpp_query(self):
        body = {
            'time': gen_time(),
            'query_type': 1,
            'query_code': config.SERVICE_ID,
            'reserve': '',
        }
        self.base_send("CMPP_QUERY", **body)

    def parse_cmpp_query_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        unpack_data = pdu.unpack(resp)
        ti = unpack_data[3]
        if self.sequence_id:
            print("time:", ti.decode())

    def cmpp_cancel(self, msg_id):
        self.base_send("CMPP_CANCEL", msg_id=msg_id)

    def parse_cmpp_cancel_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        unpack_data = pdu.unpack(resp)
        success_id = unpack_data[3]
        if self.sequence_id:
            if success_id == 0:
                self.logger.info("success")
            elif success_id == 1:
                self.logger.warning("failed")

    def cmpp_active_test(self):
        self.base_send("CMPP_ACTIVE_TEST")

    def parse_cmpp_active_test_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        unpack_data = pdu.unpack(resp)
        pdu.total_length, pdu.command_id, pdu.sequence_id = unpack_data[:-1]
        if self.sequence_id:
            print(pdu)

    def parse_cmpp_fwd(self, data, command_name):
        msg = data[265:-20]
        print("fwd消息：", msg.decode())
        pdu = gen_pdu(command_name)(msg_content=msg.decode())
        unpack_data = pdu.unpack(data)
        pdu.msg_id = unpack_data[7]
        self.cmpp_fwd_resp(pdu.msg_id)

    def cmpp_fwd_resp(self, msg_id):
        body = {
            "msg_id": msg_id,
            "pk_total": 1,
            "pk_number": 1,
            "result": 0,
        }
        self.base_send("CMPP_FWD_RESP", **body)

    def cmpp_mt_route_resp(self,resp, command_name):
        body = {
            "route_id": 0,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "start_id": "100000000",
            "end_id": "999999999",
            "area_code": "0792",
            "result": 0,
            "user_type": 0,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_MT_ROUTE_RESP", **body)

    def cmpp_mo_route_resp(self,resp, command_name):
        body = {
            "route_id": 1,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "sp_id": config.SOURCE_ADDR,
            "sp_code": config.SRC_ID,
            "sp_acess_type": 0,
            "start_code": 1000,
            "end_code": 9999,
            "result": 0,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_MO_ROUTE_RESP", **body)

    def cmpp_get_mt_route_resp(self,resp, command_name):
        body = {
            "route_id": 0,
            "destination_id": config.DESTINATION_ID,
            "gateway_ip": config.GATEWAY_IP,
            "gateway_port": config.GATEWAY_PORT,
            "start_id": "100000000",
            "end_id": "999999999",
            "area_code": "0792",
            "result": 0,
            "user_type": 0,
            "route_total": 1,
            "route_number": 1,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_GET_MT_ROUTE_RESP", **body)

    def cmpp_get_mo_route_resp(self,resp, command_name):
        body = {
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
            "result": 0,
            "route_total": 1,
            "route_number": 1,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_GET_MO_ROUTE_RESP", **body)

    def cmpp_mt_route_update_resp(self,resp, command_name):
        body = {
            "result": 0,
            "route_id": 1,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_MT_ROUTE_UPDATE_RESP", **body)

    def cmpp_mo_route_update_resp(self,resp, command_name):
        body = {
            "result": 0,
            "route_id": 1,
            "time_stamp": gen_timestamp_str()
        }
        self.base_send("CMPP_MO_ROUTE_UPDATE_RESP", **body)

    def cmpp_push_mt_route_update_resp(self,resp, command_name):
        body = {
            "result": 0,
        }
        self.base_send("CMPP_PUSH_MT_ROUTE_UPDATE_RESP", **body)

    def cmpp_push_mo_route_update_resp(self,resp, command_name):
        body = {
            "result": 0,
        }
        self.base_send("CMPP_PUSH_MO_ROUTE_UPDATE_RESP", **body)

    def fuzz(self, count, loop, interval, command_name="CMPP_CONNECT"):
        if command_name != "CMPP_CONNECT":
            self.cmpp_connect()
        for i in range(loop):
            for _ in range(count):
                fuzz_data = {
                    "CMPP_CONNECT": fuzzer.fuzz_cmpp_connect,
                    # "submit_sm": fuzzer.fuzz_submit_sm(),
                    # "enquire_link": fuzzer.fuzz_enquire_link(),
                    # "unbind": fuzzer.fuzz_unbind(),
                    # "query_sm": fuzzer.fuzz_query_sm(),
                    # "cancel_sm": fuzzer.fuzz_cancel_sm(),
                    # "replace_sm": fuzzer.fuzz_replace_sm(),
                    # "deliver_sm_resp": fuzzer.fuzz_deliver_sm_resp(),
                }
                data = fuzz_data[command_name]()
                self.logger.info(f"Starting Fuzz {self.fuzz_num}")
                try:
                    self.client.sendall(data)
                    self.logger.info(f"Fuzz {self.fuzz_num} send successfully")
                except BrokenPipeError as e:
                    self.logger.error(f"Fuzz {self.fuzz_num} BrokenPipeError: {e}")
                    with open(f"./data/err_send_data/{self.fuzz_num}", 'wb') as f:
                        f.write(data)
                    self.connect()
                    self.cmpp_connect()
                    self.client.sendall(data)
                except Exception as e:
                    self.logger.error(f"Fuzz {self.fuzz_num} failed with error: {e}")
                    with open(f"./data/err_send_data/{self.fuzz_num}", 'wb') as f:
                        f.write(data)
                finally:
                    self.fuzz_num += 1
                    time.sleep(interval)
