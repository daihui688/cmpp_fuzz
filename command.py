commands = {
    'CMPP_CONNECT': 0x00000001,  # 请求连接
    'CMPP_CONNECT_RESP': 0x80000001,  # 请求连接应答
    'CMPP_TERMINATE': 0x00000002,  # 终止连接
    'CMPP_TERMINATE_RESP': 0x80000002,  # 终止连接应答
    'CMPP_SUBMIT': 0x00000004,  # 提交短信
    'CMPP_SUBMIT_RESP': 0x80000004,  # 提交短信应答
    'CMPP_DELIVER': 0x00000005,  # 短信下发
    'CMPP_DELIVER_RESP': 0x80000005,  # 下发短信应答
    'CMPP_QUERY': 0x00000006,  # 发送短信状态查询
    'CMPP_QUERY_RESP': 0x80000006,  # 发送短信状态查询应答
    'CMPP_CANCEL': 0x00000007,  # 删除短信
    'CMPP_CANCEL_RESP': 0x80000007,  # 删除短信应答
    'CMPP_ACTIVE_TEST': 0x00000008,  # 激活测试
    'CMPP_ACTIVE_TEST_RESP': 0x80000008,  # 激活测试应答
    'CMPP_FWD': 0x00000009,  # 消息前转
    'CMPP_FWD_RESP': 0x80000009,  # 消息前转应答
    'CMPP_MT_ROUTE': 0x00000010,  # MT 路由请求
    'CMPP_MT_ROUTE_RESP': 0x80000010,  # MT 路由请求应答
    'CMPP_MO_ROUTE': 0x00000011,  # MO 路由请求
    'CMPP_MO_ROUTE_RESP': 0x80000011,  # MO 路由请求应答
    'CMPP_GET_MT_ROUTE': 0x00000012,  # 获取 MT 路由请求
    'CMPP_GET_MT_ROUTE_RESP': 0x80000012,  # 获取 MT 路由请求应答
    'CMPP_MT_ROUTE_UPDATE': 0x00000013,  # MT 路由更新
    'CMPP_MT_ROUTE_UPDATE_RESP': 0x80000013,  # MT 路由更新应答
    'CMPP_MO_ROUTE_UPDATE': 0x00000014,  # MO 路由更新
    'CMPP_MO_ROUTE_UPDATE_RESP': 0x80000014,  # MO 路由更新应答
    'CMPP_PUSH_MT_ROUTE_UPDATE': 0x00000015,  # MT 路由更新
    'CMPP_PUSH_MT_ROUTE_UPDATE_RESP': 0x80000015,  # MT 路由更新应答
    'CMPP_PUSH_MO_ROUTE_UPDATE': 0x00000016,  # MO 路由更新
    'CMPP_PUSH_MO_ROUTE_UPDATE_RESP': 0x80000016,  # MO 路由更新应答
    'CMPP_GET_MO_ROUTE': 0x00000017,  # 获取 MO 路由请求
    'CMPP_GET_MO_ROUTE_RESP': 0x80000017,  # 获取 MO 路由请求应答
}


def get_command_id(command_name):
    return commands.get(command_name)


def get_command_name(command_id):
    for name, _id in commands.items():
        if _id == command_id:
            return name
