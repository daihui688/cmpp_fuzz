CMPP_CONNECT_RESP_Status = {
    0: "正确",
    1: "消息结构错",
    2: "非法源地址",
    3: "认证错",
    4: "版本太高",
    5: "其他错误"
}
Fee_UserType_Description = {
    0: "对目的终端MSISDN计费",
    1: "对源终端MSISDN计费",
    2: "对SP计费",
    3: "表示本字段无效，对谁计费参见Fee_terminal_Id字段",
}
Msg_Fmt = {
    0: "ascii",  # ASCII串
    3: "短信写卡操作",
    4: "二进制信息",
    8: "utf-16",  # UCS2编码
    15: "含GB汉字",
}
FeeType_Description = {
    "01": "对计费用户号码免费",
    "02": "对计费用户号码按条计信息费",
    "03": "对计费用户号码按包月收取信息费",
    "04": "对计费用户号码的信息费封顶",
    "05": "对计费用户号码的收费是由SP实现",
}
CMPP_SUBMIT_RESP_Result = {
    0: "正确",
    1: "消息结构错",
    2: "命令字错",
    3: "消息序号重复",
    4: "消息长度错",
    5: "资费代码错",
    6: "超过最大信息长",
    7: "业务代码错",
    8: "流量控制错",
    9: "本网关不负责服务此计费号码",
    10: "Src_Id错误",
    11: "Msg_src错误",
    12: "Fee_terminal_Id错误",
    13: "Dest_terminal_Id错误",
}

Msg_Content_Stat = {
    "delivrd": "Message is delivered to destination",
    "expired": "Message validity period has expired",
    "deleted": "Message has been deleted",
    "undeliv": "Message is undeliverable",
    "acceptd": "Message is in accepted state(i.e. has been manually read on behalf of the subscriber by customer service)",
    "unknown": "Message is in invalid state",
    "rejectd": "Message is in a rejected state",
    "MA:xxxx": "SMSC 不返回响应消息时的状态报告",
    "MB:xxxx": "SMSC 返回错误响应消息时的状态报告",
    "CA:xxxx": "SCP 不返回响应消息时的状态报告",
    "CB:xxxx": "SCP 返回错误响应消息时的状态报告",
}
CMPP_FWD_RESP_Result = {
    0: "正确",
    1: "消息结构错",
    2: "命令字错",
    3: "消息序号重复",
    4: "消息长度错",
    5: "资费代码错",
    6: "超过最大信息长",
    7: "业务代码错",
    8: "流量控制错",
    9: "前转判断错(此SP不应发往本ISMG)",
    10: "其他错误"
}
Msg_Fwd_Type = {
    0: "MT前转",
    1: "MO前转",
    2: "MT时的状态报告",
    3: "MO时的状态报告",
}
CMPP_MT_ROUTE_RESP_Result = {
    0: "正常",
    1: "没有匹配路由",
    2: "源网关代码错",
    9: "系统繁忙",
}
CMPP_MO_ROUTE_RESP_Result = CMPP_MT_ROUTE_RESP_Result

User_type = {
    0: "全球通",
    1: "神州行",
    2: "M-Zone"
}

Update_type = {
    0: "添加",
    1: "删除",
    2: "更新"
}

CMPP_MT_ROUTE_UPDATE_RESP_result = {
    0: "数据合法，等待核实",
    4: "本节点不支持更新（GNS分节点）",
    9: "系统繁忙",
    10: "Update_type错误",
    11: "路由编号错误",
    12: "目的网关代码错误",
    13: "目的网关IP错误",
    14: "目的网关Port错误",
    15: "MT路由起始号码段错误",
    16: "MT路由截止号码段错误",
    17: "手机所属省代码错误",
    18: "用户类型错误",
}
CMPP_MO_ROUTE_UPDATE_RESP_result = {
    0: "数据合法，等待核实",
    4: "本节点不支持更新（GNS 分节点）",
    9: "系统繁忙",
    10: "Update_type错误",
    11: "路由编号错误",
    12: "目的网关代码错误",
    13: "目的网关IP错误",
    14: "目的网关Port错误",
    19: "SP_Id错误",
    20: "SP_Code错误",
    21: "SP_AccessType错误",
    22: "Service_Id错误",
    23: "Start_code错误",
    24: "End_code错误",
}
CMPP_PUSH_MT_ROUTE_UPDATE_RESP_Result = {
    0:"成功更改",
    5:"路由信息更新失败",
    6:"汇接网关路由信息时间戳比本地路由信息时间戳旧",
    9:"系统繁忙",
}

INT_PACK_FORMATS = {
    1:"B",
    2:"H",
    4:"L",
    8:"Q"
}
