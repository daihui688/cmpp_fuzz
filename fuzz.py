from faker import Faker

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

    @staticmethod
    def random_ints(num):
        return fake.random_int(0xff * (num - 1), 0xff * num)

    @property
    def random_byte(self):
        return bytes([self.random_int])

    def random_bytes(self, num):
        data = b''
        for i in range(num):
            data += self.random_byte
        return data

    def gen_body(self, command_name):
        body = b''
        pdu = get_pdu(command_name)
        try:
            pdu.body
        except AttributeError:
            return body
        for k, v in pdu.body.items():
            param = b''
            if k == "dest_usr_tl":
                param = b'\x01'
            if v.type == str:
                size = v.size
                if not v.size:
                    size = self.random_int
                param = struct.pack(f">{size}s", self.random_strs(size).encode())
            elif v.type == int:
                c = const.INT_PACK_FORMATS.get(v.size)
                param = struct.pack(">" + c, self.random_ints(v.size))
                if k == "timestamp":
                    param = struct.pack(">" + c, gen_timestamp())
            body += param
        return body

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

    def fuzz_data(self, command_name):
        body = self.gen_body(command_name)
        data = self.gen_data(command_name, body)
        return data


fuzzer = CMPPFuzz()
