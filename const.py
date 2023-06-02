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
    0: "ascii", # ASCII串
    3: "短信写卡操作",
    4: "二进制信息",
    8: "utf-16", # UCS2编码
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
    0:"正确",
    1:"消息结构错",
    2:"命令字错",
    3:"消息序号重复",
    4:"消息长度错",
    5:"资费代码错",
    6:"超过最大信息长",
    7:"业务代码错",
    8:"流量控制错",
    9:"本网关不负责服务此计费号码",
    10:"Src_Id错误",
    11:"Msg_src错误",
    12:"Fee_terminal_Id错误",
    13:"Dest_terminal_Id错误",
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
    0:"正确",
    1:"消息结构错",
    2:"命令字错",
    3:"消息序号重复",
    4:"消息长度错",
    5:"资费代码错",
    6:"超过最大信息长",
    7:"业务代码错",
    8:"流量控制错",
    9:"前转判断错(此SP不应发往本ISMG)",
    10:"其他错误"
}
Msg_Fwd_Type = {
    0:"正确",
    1:"消息结构错",
    2:"命令字错",
    3:"消息序号重复",
}