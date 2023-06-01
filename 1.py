import struct

# data = struct.pack(">I",b'\x1f\x88\x24\x96')
# print(data)
# print(0x1f882496)

# text = "Hello, 你好"  # 要编码的字符串
#
# # 将字符串编码为UCS2
# encoded_text = text.encode('utf-16')
#
# # 打印编码后的字节数据
# print(encoded_text)

import datetime


def generate_msg_id(gateway_code, sequence_number):
    current_time = datetime.datetime.now()
    month = current_time.month
    day = current_time.day
    hour = current_time.hour
    minute = current_time.minute
    second = current_time.second

    # 构建Msg_Id的各个部分
    time_part = (month << 60) | (day << 56) | (hour << 51) | (minute << 45) | (second << 39)
    gateway_part = gateway_code << 17
    sequence_part = sequence_number

    # 合并各部分并返回Msg_Id
    msg_id = (time_part | gateway_part | sequence_part)
    return msg_id


# 示例用法
gateway_code = 12345
sequence_number = 1
msg_id = generate_msg_id(gateway_code, sequence_number)
print(msg_id)


