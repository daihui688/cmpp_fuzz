from faker import Faker
import struct

import command
from utils import *
fake = Faker()
ascii_chars = ''.join(chr(i) for i in range(128))


class CMPPFuzz:
    def __init__(self):
        self.sequence_id = 0

    @property
    def random_char(self):
        return fake.lexify(text="?", letters=ascii_chars)

    @property
    def random_str(self):
        return fake.lexify(text="?" * fake.random_int(0, 200), letters=ascii_chars)

    @staticmethod
    def random_strs(num):
        return fake.lexify(text="?" * num, letters=ascii_chars)

    @property
    def random_int(self):
        return fake.random_int(0x00, 0xff)

    @property
    def random_byte(self):
        return bytes([self.random_int])

    def random_bytes(self, num):
        data = b''
        for i in range(num):
            data += self.random_byte
        return data

    def gen_data(self, command_name, body=None):
        command_id = command.get_command_id(command_name)
        self.sequence_id += 1
        if not body:
            total_length = 12
            header = struct.pack(">3I", total_length, command_id, self.sequence_id)
            return header
        else:
            total_length = 12 + len(body)
            header = struct.pack(">3I", total_length, command_id, self.sequence_id)
            data = header + body
            return data

    def fuzz_cmpp_connect(self):

        # body = {
        #     'source_addr': Param(type=str, size=6),
        #     'authenticator_source': Param(type=str, size=16),
        #     'version': Param(type=int, size=1),
        #     'timestamp': Param(type=int, size=4),
        # }

        source_addr = self.random_bytes(6)
        authenticator_source = self.random_bytes(16)
        version = self.random_int
        timestamp = gen_timestamp()

        body = source_addr + authenticator_source + struct.pack(">BI",version,timestamp)
        data = self.gen_data("CMPP_CONNECT", body)
        return data

    def fuzz_submit_sm(self):
        pass

    def fuzz_unbind(self):
        return self.gen_data("unbind")

    def fuzz_enquire_link(self):
        return self.gen_data("enquire_link")

    def fuzz_query_sm(self):
        # body = {
        #     'message_id': Param(type=str, max=65),
        #     'source_addr_ton': Param(type=int, size=1),
        #     'source_addr_npi': Param(type=int, size=1),
        #     'source_addr': Param(type=str, max=21),
        # }
        message_id = str(fake.random_int(1, 100)).encode() + b'\x00'
        source_addr = self.random_bytes(21) + b'\x00'
        body = message_id + self.random_bytes(2) + source_addr
        data = self.gen_data("query_sm", body)
        return data

    def fuzz_cancel_sm(self):
        # params = {
        #     'service_type': Param(type=str, max=6),
        #     'message_id': Param(type=str, max=65),
        #     'source_addr_ton': Param(type=int, size=1),
        #     'source_addr_npi': Param(type=int, size=1),
        #     'source_addr': Param(type=str, max=21),
        #     'dest_addr_ton': Param(type=int, size=1),
        #     'dest_addr_npi': Param(type=int, size=1),
        #     'destination_addr': Param(type=str, max=21),
        # }
        message_id = str(fake.random_int(1, 100)).encode() + b'\x00'
        source_addr = self.random_bytes(21) + b'\x00'
        destination_addr = self.random_bytes(21) + b'\x00'
        body = b'\x00' + message_id + self.random_bytes(2) + source_addr + self.random_bytes(2) + \
               destination_addr
        data = self.gen_data("cancel_sm", body)
        return data

    def fuzz_replace_sm(self):
        # body = {
        #     'message_id': Param(type=str, max=65),
        #     'source_addr_ton': Param(type=int, size=1),
        #     'source_addr_npi': Param(type=int, size=1),
        #     'source_addr': Param(type=str, max=21),
        #     'schedule_delivery_time': Param(type=int, max=17),
        #     'validity_period': Param(type=int, max=17),
        #     'registered_delivery': Param(type=int, size=1),
        #     'sm_default_msg_id': Param(type=int, size=1),
        #     'sm_length': Param(type=int, size=1),
        #     'short_message': Param(type=str, max=254, len_field='sm_length'),
        # }
        message_id = str(fake.random_int(1, 100)).encode() + b'\x00'
        source_addr = self.random_bytes(21) + b'\x00'
        sm_length = fake.random_int(0, 254)
        body = message_id + self.random_bytes(2) + source_addr + b'\x00' + b'\x00' + \
               self.random_bytes(2) + struct.pack(">B", sm_length) + self.random_bytes(sm_length)
        data = self.gen_data("replace_sm", body)
        return data

    def fuzz_deliver_sm_resp(self):
        command_id = command.get_command_id("deliver_sm_resp")
        command_status = 0
        self.sequence_id += 1
        data = struct.pack(">LLLLc", 17, command_id, command_status, self.sequence_id, b'\x00')
        return data


fuzzer = CMPPFuzz()
