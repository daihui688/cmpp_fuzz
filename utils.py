import hashlib
import datetime
import netifaces

import config
from pdu import *

now = datetime.datetime.now()
def gen_pdu(command_name):
    """生成PDU"""
    try:
        return {
            'CMPP_CONNECT': CmppConnectPDU,  # 请求连接
            'CMPP_CONNECT_RESP': CmppConnectRespPDU,  # 请求连接应答
            'CMPP_TERMINATE': CmppTerminatePDU,  # 终止连接
            'CMPP_TERMINATE_RESP': CmppTerminateRespPDU,  # 终止连接应答
            'CMPP_SUBMIT': CmppSubmitPDU,  # 提交短信
            'CMPP_SUBMIT_RESP': CmppSubmitRespPDU,  # 提交短信应答
            'CMPP_DELIVER': CmppDeliverPDU,  # 短信下发
            'CMPP_DELIVER_RESP': CmppDeliverRespPDU,  # 下发短信应答
            'CMPP_QUERY': CmppQueryPDU,  # 发送短信状态查询
            'CMPP_QUERY_RESP': CmppQueryRespPDU,  # 发送短信状态查询应答
            'CMPP_CANCEL': CmppCancelPDU,  # 删除短信
            'CMPP_CANCEL_RESP': CmppCancelRespPDU,  # 删除短信应答
            'CMPP_ACTIVE_TEST': CmppActiveTestPDU,  # 激活测试
            'CMPP_ACTIVE_TEST_RESP': CmppActiveTestRespPDU,  # 激活测试应答
            'CMPP_FWD': CmppFwdPDU,  # 消息前转
            'CMPP_FWD_RESP': CmppFwdRespPDU,  # 消息前转应答
            # 'CMPP_MT_ROUTE': 0x00000010,  # MT 路由请求
            # 'CMPP_MT_ROUTE_RESP': 0x80000010,  # MT 路由请求应答
            # 'CMPP_MO_ROUTE': 0x00000011,  # MO 路由请求
            # 'CMPP_MO_ROUTE_RESP': 0x80000011,  # MO 路由请求应答
            # 'CMPP_GET_MT_ROUTE': 0x00000012,  # 获取 MT 路由请求
            # 'CMPP_GET_MT_ROUTE_RESP': 0x80000012,  # 获取 MT 路由请求应答
            # 'CMPP_MT_ROUTE_UPDATE': 0x00000013,  # MT 路由更新
            # 'CMPP_MT_ROUTE_UPDATE_RESP': 0x80000013,  # MT 路由更新应答
            # 'CMPP_MO_ROUTE_UPDATE': 0x00000014,  # MO 路由更新
            # 'CMPP_MO_ROUTE_UPDATE_RESP': 0x80000014,  # MO 路由更新应答
            # 'CMPP_PUSH_MT_ROUTE_UPDATE': 0x00000015,  # MT 路由更新
            # 'CMPP_PUSH_MT_ROUTE_UPDATE_RESP': 0x80000015,  # MT 路由更新应答
            # 'CMPP_PUSH_MO_ROUTE_UPDATE': 0x00000016,  # MO 路由更新
            # 'CMPP_PUSH_MO_ROUTE_UPDATE_RESP': 0x80000016,  # MO 路由更新应答
            # 'CMPP_GET_MO_ROUTE': 0x00000017,  # 获取 MO 路由请求
            # 'CMPP_GET_MO_ROUTE_RESP': 0x80000017,  # 获取 MO 路由请求应答
        }[command_name]
    except KeyError:
        raise Exception('Command "%s" is not supported' % command_name)


def contains_chinese(message):
    for char in message:
        if '\u4e00' <= char <= '\u9fff':
            return True
    return False


def get_interfaces_and_ips():
    interfaces_ips = {}
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_address = addrs[netifaces.AF_INET][0]['addr']
            interfaces_ips[iface] = ip_address
    return interfaces_ips

def full(s:int):
    if len(str(s)) == 1:
        return "0" + str(s)
    return str(s)

def gen_timestamp():
    return int(full(now.month) + full(now.day) + full(now.hour) + full(now.minute) + full(now.second))


def gen_time():
    return full(now.year) + full(now.month) + full(now.day)


def gen_authenticator_source(source_addr=config.SOURCE_ADDR, shared_secret=config.SHARED_SECRET,
                             timestamp=gen_timestamp()):
    # 拼接待加密的数据
    data = source_addr + '\x00' * 9 + shared_secret + str(timestamp)
    md5 = hashlib.md5()
    md5.update(data.encode())
    authenticator_source = md5.digest()
    return authenticator_source


def gen_authenticator_ismg(status, authenticator_source, shared_secret=config.SHARED_SECRET):
    data = str(status) + authenticator_source.hex() + shared_secret
    md5 = hashlib.md5()
    md5.update(data.encode())
    authenticator_ismg = md5.digest()
    return authenticator_ismg


def gen_msg_id(sequence_id, gateway_code=106):
    current_time = datetime.datetime.now()
    month = current_time.month
    day = current_time.day
    hour = current_time.hour
    minute = current_time.minute
    second = current_time.second

    # 构建时间部分
    time_part = (month << 60) | (day << 56) | (hour << 51) | (minute << 45) | (second << 39)

    # 构建短信网关代码部分
    gateway_part = gateway_code << 17

    # 构建序列号部分
    sequence_part = sequence_id

    # 合并各部分并返回Msg_Id
    msg_id = (time_part | gateway_part | sequence_part)
    return msg_id

if __name__ == '__main__':
    print(gen_time())
