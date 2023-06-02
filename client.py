import logging
import socket
import threading
import time

from command import get_command_id, get_command_name
# from fuzz import fuzzer
from utils import *


class SP:
    def __init__(self, host):
        self.host = host
        self.client = None
        self.sequence_id = 0
        self.connect_ismg = False
        self.msg_fmt = 0
        self.last_msg_id = None
        self.fuzz_num = 0
        self.is_first_handle = True

        # Set up logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

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
            t1 = threading.Thread(target=self.handle)
            t1.start()
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
        self.cmpp_connect()
        time.sleep(1)
        t2 = threading.Thread(target=self.active_test)
        t2.start()
        while True:
            option = input("请输入你要执行的操作编号(0.测试,1.发送消息):")
            if option == "0":
                self.cmpp_query()
                time.sleep(interval)
                self.cmpp_cancel(self.last_msg_id)
                time.sleep(interval)
            elif option == "1":
                for i in range(count):
                    msg = input("请输入你要发送的消息:")
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
            if self.is_first_handle is False and self.connect_ismg is False:
                self.logger.warning("handle() exit!")
                break
            length = self.client.recv(4)
            command_length = struct.unpack(">I", length)[0]
            resp = length + self.client.recv(command_length - 4)
            command_id = struct.unpack(">L", resp[4:8])[0]
            command_name = get_command_name(command_id)
            if command_name == "CMPP_CONNECT_RESP":
                self.is_first_handle = False
                self.parse_cmpp_connect_resp(resp, command_name)
            elif command_name == "CMPP_TERMINATE_RESP":
                self.parse_cmpp_terminate_resp(resp, command_name)
            elif command_name == "CMPP_SUBMIT_RESP":
                self.parse_cmpp_submit_resp(resp, command_name)
            elif command_name == "CMPP_DELIVER":
                self.parse_cmpp_deliver(resp, command_name)
            # elif command_name == "data_sm_resp":
            #     self.parse_data_sm_resp(resp, command_name)
            elif command_name == "CMPP_QUERY_RESP":
                self.parse_cmpp_query_resp(resp, command_name)
            elif command_name == "CMPP_ACTIVE_TEST_RESP":
                self.parse_cmpp_active_test_resp(resp, command_name)
            elif command_name == "CMPP_CANCEL_RESP":
                self.parse_cmpp_cancel_resp(resp, command_name)
            elif command_name == "CMPP_ACTIVE_TEST_RESP":
                self.parse_cmpp_active_test_resp(resp, command_name)
            # else:
            #     self.logger.error("异常数据")
            #     with open(f"./data/err_resp_data/{self.fuzz_num}", "wb") as f:
            #         f.write(resp)

    def active_test(self):
        while True:
            if not self.connect_ismg:
                break
            try:
                self.cmpp_active_test()
                time.sleep(60)
            except Exception as e:
                self.logger.error(e)
                break
    def base_send(self, command_name, **kwargs):
        command_id = get_command_id(command_name)
        self.sequence_id += 1
        pdu = gen_pdu(command_name)(command_id=command_id, sequence_id=self.sequence_id,**kwargs)
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
            'version':config.VERSION,
            'timestamp': timestamp,
        }
        self.base_send("CMPP_CONNECT", **body)
    def parse_cmpp_connect_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        resp_data = pdu.unpack(resp)
        pdu.total_length, pdu.command_id, pdu.sequence_id, pdu.status, pdu.authenticatorISMG,pdu.version = resp_data
        if pdu.sequence_id == self.sequence_id and pdu.status == 0:
            self.logger.info(f"与ISMG连接成功,{pdu}")
            self.connect_ismg = True
    def cmpp_terminate(self):
        self.base_send("CMPP_TERMINATE")

    def parse_cmpp_terminate_resp(self, resp, command_name):
        pdu = self.parse_base_resp(resp, command_name)
        print(pdu.sequence_id ,self.sequence_id)
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
            'fee_terminal_id': "18279230916",
            'fee_terminal_type': 0,
            'tp_pid': 1,
            'tp_udhi': 1,
            'msg_fmt': self.msg_fmt,
            'msg_src': config.SOURCE_ADDR,
            'fee_type': "02",
            'fee_code': "000001",
            'valid_time': "20230601120000",
            'at_time': "20230531155000",
            'src_id': "18279230916",
            'dest_usr_tl': 1,
            'dest_terminal_id': "+8613520376620",
            'dest_terminal_type': 0,
            'msg_content': msg,
            'link_id': "",
        }
        self.base_send("CMPP_SUBMIT", **body)

    def parse_cmpp_submit_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        resp_data = pdu.unpack(resp)
        pdu.total_length, pdu.command_id, pdu.sequence_id, pdu.msg_id,pdu.result = resp_data
        if pdu.sequence_id == self.sequence_id:
            self.logger.info(f"发送消息成功,{pdu}")
            self.last_msg_id = pdu.msg_id

    # def data_sm(self, message):
    #     # body = {
    #     #     "service_type": consts.NULL_BYTE,
    #     #     "source_addr_ton": consts.SMPP_TON_INTL,
    #     #     "source_addr_npi": consts.SMPP_NPI_ISDN,
    #     #     "source_addr": config.SOURCE_ADDR,
    #     #     "dest_addr_ton": consts.SMPP_TON_INTL,
    #     #     "dest_addr_npi": consts.SMPP_NPI_ISDN,
    #     #     "destination_addr": config.DESTINATION_ADDR,
    #     #     "esm_class": consts.NULL_BYTE,
    #     #     "registered_delivery": consts.SMPP_SMSC_DELIVERY_RECEIPT_BOTH,
    #     #     "data_coding": self.data_coding,
    #     #     "short_message": message
    #     # }
    #     self.base_send_sm("data_sm", **body)

    # def parse_data_sm_resp(self, resp, command_name):
    #     message_id = resp[16:-1]
    #     pdu = get_pdu(command_name)(message_id=message_id)
    #     resp_data = pdu.unpack(resp)
    #     pdu.command_length, pdu.command_id, pdu.command_status, pdu.sequence_number, pdu.message_id = resp_data[:-1]
    #     if pdu.sequence_number == self.sequence_number and pdu.command_status == consts.SMPP_ESME_ROK:
    #         self.logger.info(f"发送消息成功,{pdu}")

    # def parse_deliver_sm(self, resp, command_name):
    #     sm_length = resp[56]
    #     # short_message = resp[57:57 + sm_length]
    #     optional_params = resp[57 + sm_length:]
    #     # print(sm_length)
    #     # print(short_message)
    #     # print(optional_params)
    #     pdu = get_pdu(command_name)(source_addr=config.SOURCE_ADDR, destination_addr=config.DESTINATION_ADDR,
    #                                 sm_length=sm_length, optional_params=optional_params)
    #     resp_data = pdu.unpack(resp)
    #     pdu.command_length, pdu.command_id, pdu.command_status, pdu.sequence_number = resp_data[:4]
    #     pdu.optional_params = resp_data[-1]
    #     if sm_length != 0:
    #         pdu.short_message = resp_data[-2]
    #     else:
    #         pdu.optional_params = resp_data[-1]
    #         # optional_param_type = struct.unpack(">H", pdu.optional_params[:2])[0]
    #         # optional_param_name = get_optional_param_name(optional_param_type)
    #         # print(optional_param_name)
    #         optional_param_length = struct.unpack(">H", pdu.optional_params[2:4])[0]
    #         # print(optional_param_length)
    #         payload = pdu.optional_params[4:4 + optional_param_length]
    #         data = payload[94:-9]
    #         print(data.decode())
    #     if pdu.command_status == consts.SMPP_ESME_ROK:
    #         self.deliver_sm_resp(pdu.sequence_number)
    def parse_cmpp_deliver(self,data,command_name):
        msg = data[89:-20]
        print("收到ISMG投递消息：",msg.decode())
        pdu = gen_pdu(command_name)(msg_content=msg.decode())
        unpack_data = pdu.unpack(data)
        pdu.msg_id = unpack_data[3]
        self.cmpp_deliver_resp(pdu.msg_id)
    def cmpp_deliver_resp(self, msg_id):
        body = {
            "msg_id": msg_id,
            "result": 0,
        }
        self.base_send("CMPP_DELIVER_RESP",**body)

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
            print("time:",ti.decode())

    # def cancel_sm(self, message_id):
    #     body = {
    #         "service_type": consts.NULL_BYTE,
    #         'message_id': message_id,
    #         'source_addr_ton': consts.SMPP_TON_INTL,
    #         "source_addr_npi": consts.SMPP_NPI_ISDN,
    #         'source_addr': config.SOURCE_ADDR,
    #         "dest_addr_ton": consts.SMPP_TON_INTL,
    #         "dest_addr_npi": consts.SMPP_NPI_ISDN,
    #         "destination_addr": config.DESTINATION_ADDR,
    #     }
    #     self.base_send_sm("cancel_sm", **body)

    def cmpp_cancel(self,msg_id):
        self.base_send("CMPP_CANCEL",msg_id=msg_id)
    def parse_cmpp_cancel_resp(self, resp, command_name):
        pdu = gen_pdu(command_name)()
        unpack_data = pdu.unpack(resp)
        success_id = unpack_data[3]
        if self.sequence_id:
            if success_id == 0:
                self.logger.info("success")
            elif success_id == 1:
                self.logger.warning("failed")

    # def replace_sm(self, message_id, new_message):
    #     body = {
    #         'message_id': message_id,
    #         'source_addr_ton': consts.SMPP_TON_INTL,
    #         "source_addr_npi": consts.SMPP_NPI_ISDN,
    #         'source_addr': config.SOURCE_ADDR,
    #         'schedule_delivery_time': 0,
    #         'validity_period': 0,
    #         'registered_delivery': consts.SMPP_SMSC_DELIVERY_RECEIPT_BOTH,
    #         'sm_default_msg_id': 0,
    #         'short_message': new_message,
    #         "data_coding": self.data_coding
    #     }
    #     self.base_send_sm("replace_sm", **body)

    def parse_replace_sm_resp(self, resp, command_name):
        pdu = self.parse_base_resp(resp, command_name)
        if pdu.sequence_number == self.sequence_number:
            self.logger.info(f"{command_name}:{pdu}")



    def cmpp_active_test(self):
        self.base_send("CMPP_ACTIVE_TEST")

    def parse_cmpp_active_test_resp(self, resp, command_name):
        pdu = self.parse_base_resp(resp, command_name)
        if pdu.sequence_id == self.sequence_id:
            print(pdu)


    # def fuzz(self, count, loop, interval, command_name="submit_sm"):
    #     if command_name != "bind_transceiver":
    #         self.bind()
    #     for i in range(loop):
    #         for _ in range(count):
    #             fuzz_data = {
    #                 "bind_transceiver": fuzzer.fuzz_bind_transceiver(),
    #                 "submit_sm": fuzzer.fuzz_submit_sm(),
    #                 "enquire_link": fuzzer.fuzz_enquire_link(),
    #                 "unbind": fuzzer.fuzz_unbind(),
    #                 "query_sm": fuzzer.fuzz_query_sm(),
    #                 "cancel_sm": fuzzer.fuzz_cancel_sm(),
    #                 "replace_sm": fuzzer.fuzz_replace_sm(),
    #                 "deliver_sm_resp": fuzzer.fuzz_deliver_sm_resp(),
    #             }
    #             data = fuzz_data[command_name]
    #             self.logger.info(f"Starting fuzz {self.fuzz_num}")
    #             try:
    #                 self.client.sendall(data)
    #                 self.logger.info(f"Fuzz {self.fuzz_num} send successfully")
    #             except BrokenPipeError as e:
    #                 self.logger.error(f"Fuzz {self.fuzz_num} BrokenPipeError: {e}")
    #                 with open(f"./data/err_send_data/{self.fuzz_num}", 'wb') as f:
    #                     f.write(data)
    #                 self.connect()
    #                 self.bind()
    #                 self.client.sendall(data)
    #             except Exception as e:
    #                 self.logger.error(f"Fuzz {self.fuzz_num} failed with error: {e}")
    #                 with open(f"./data/err_send_data/{self.fuzz_num}", 'wb') as f:
    #                     f.write(data)
    #             finally:
    #                 self.fuzz_num += 1
    #                 time.sleep(interval)


