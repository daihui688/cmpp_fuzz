import struct

import const


class Param:
    def __init__(self, type, size=None):
        self.type = type
        self.size = size


class PDU:
    header = {
        "total_length": Param(type=int, size=4),
        "command_id": Param(type=int, size=4),
        "sequence_id": Param(type=int, size=4)
    }

    def __init__(self, grammar=">3I"):
        self.struct = struct.Struct(grammar)
        self.total_length = self.struct.size
        self.pack_param = []

    def _set_vals(self, d):
        for k, v in d.items():
            setattr(self, k, v)

    def gen_pack_param(self):
        for k, v in self.header.items():
            param = getattr(self, k)
            self.pack_param.append(param)
        try:
            self.body
        except AttributeError:
            return
        for k, v in self.body.items():
            param = getattr(self, k)
            if v.type == str:
                value = getattr(self, k)
                if type(value) == str:
                    param = value.encode()
                    if k == "msg_content":
                        param = self.message_bytes
            self.pack_param.append(param)

    def pack(self):
        self.gen_pack_param()
        data = self.struct.pack(*self.pack_param)
        return data

    def unpack(self, resp):
        return self.struct.unpack(resp)

    def gen_msg_bytes(self):
        try:
            return self.msg_content.encode(const.Msg_Fmt[self.msg_fmt])
        except Exception:
            return self.msg_content.encode('ascii')

    def __str__(self):
        s = 'PDU('
        for k in self.header:
            s += f"{k}:{getattr(self,k)},"
        try:
            self.body
        except AttributeError:
            pass
        for k in self.body:
            s += f"{k}:{getattr(self,k)},"
        return s + ')'

class HeaderPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


class CmppConnectPDU(PDU):
    """
    SP信息资源站实体->ISMG互联网短信网关
    """
    body = {
        'source_addr': Param(type=str, size=6),
        'authenticator_source': Param(type=str, size=16),
        'version': Param(type=int, size=1),
        'timestamp': Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3I6s16sBI"
        super().__init__(grammar)


class CmppConnectRespPDU(PDU):
    body = {
        "status": Param(type=int, size=4),
        "authenticatorISMG": Param(type=str, size=16),
        "version": Param(type=int, size=1)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I16sB"
        super().__init__(grammar)



class CmppTerminatePDU(HeaderPDU):
    pass


class CmppTerminateRespPDU(HeaderPDU):
    pass


class CmppSubmitPDU(PDU):
    body = {
        'msg_id': Param(type=int, size=8),
        'pk_total': Param(type=int, size=1),
        'pk_number': Param(type=int, size=1),
        'registered_delivery': Param(type=int, size=1),
        'msg_level': Param(type=int, size=1),
        'service_id': Param(type=str, size=10),
        'fee_usertype': Param(type=int, size=1),
        'fee_terminal_id': Param(type=str, size=32),
        'fee_terminal_type': Param(type=int, size=1),
        'tp_pid': Param(type=int, size=1),
        'tp_udhi': Param(type=int, size=1),
        'msg_fmt': Param(type=int, size=1),
        'msg_src': Param(type=str, size=6),
        'fee_type': Param(type=str, size=2),
        'fee_code': Param(type=str, size=6),
        'valid_time': Param(type=str, size=17),
        'at_time': Param(type=str, size=17),
        'src_id': Param(type=str, size=21),
        'dest_usr_tl': Param(type=int, size=1),
        'dest_terminal_id': Param(type=str, size=32),
        'dest_terminal_type': Param(type=int, size=1),
        'msg_length': Param(type=int, size=1),
        'msg_content': Param(type=str),
        'link_id': Param(type=str, size=20),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        try:
            if self.msg_content:
                self.msg_bytes = self.gen_msg_bytes()
        except AttributeError:
            pass
        self.msg_length = len(self.msg_bytes)
        grammar = f">3IQ4B10sB32s4B6s2s6s17s17s21sB32s2B{self.msg_length}s20s"
        super().__init__(grammar)


class CmppSubmitRespPDU(PDU):
    body = {
        "msg_id": Param(type=int, size=8),
        "result": Param(type=int, size=4)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQI"
        super().__init__(grammar)



class CmppDeliverPDU(PDU):
    body = {
        'msg_id': Param(type=int, size=8),
        'dest_id': Param(type=str, size=21),
        'service_id': Param(type=str, size=10),
        'tp_pid': Param(type=int, size=1),
        'tp_udhi': Param(type=int, size=1),
        'msg_fmt': Param(type=int, size=1),
        'src_terminal_id': Param(type=str, size=32),
        'src_terminal_type': Param(type=int, size=1),
        'registered_delivery': Param(type=int, size=1),
        'msg_length': Param(type=int, size=1),
        'msg_content': Param(type=str),
        'link_id': Param(type=str, size=20),
    }
    # 如果要发送状态报告
    msg_content = {
        "msg_id": Param(type=int, size=8),
        "Stat": Param(type=str, size=7),
        "Submit_time": Param(type=str, size=10),
        "Done_time": Param(type=str, size=10),
        "Dest_terminal_Id": Param(type=str, size=21),
        "SMSC_sequence": Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        try:
            if self.msg_content:
                self.msg_bytes = self.gen_msg_bytes()
        except AttributeError:
            pass
        self.msg_length = len(self.msg_bytes)
        grammar = f">3IQ21s10s3B32s3B{self.msg_length}s20s"
        super().__init__(grammar)


class CmppDeliverRespPDU(PDU):
    body = {
        "msg_id": Param(type=int, size=8),
        "result": Param(type=int, size=4)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQI"
        super().__init__(grammar)




class CmppQueryPDU(PDU):
    body = {
        'time': Param(type=str, size=8),
        'query_type': Param(type=int, size=1),
        'query_code': Param(type=str, size=10),
        'reserve': Param(type=str, size=8),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3I8sB10s8s"
        super().__init__(grammar)


class CmppQueryRespPDU(PDU):
    body = {
        'time': Param(type=str, size=8),
        'query_type': Param(type=int, size=1),
        'query_code': Param(type=str, size=10),
        'mt_tl_msg': Param(type=int, size=4),  # 从SP接收信息总数
        'mt_tl_usr': Param(type=int, size=4),  # 从SP接收用户总数
        'mt_scs': Param(type=int, size=4),  # 成功转发数量
        'mt_wt': Param(type=int, size=4),  # 待转发数量
        'mt_fl': Param(type=int, size=4),  # 转发失败数量
        'mo_scs': Param(type=int, size=4),  # 向SP成功送达数量
        'mo_wt': Param(type=int, size=4),  # 向SP待送达数量
        'mo_fl': Param(type=int, size=4),  # 向SP送达失败数量
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3I8sB10s8I"
        super().__init__(grammar)




class CmppCancelPDU(PDU):
    body = {
        'msg_id': Param(type=int, size=8),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQ"
        super().__init__(grammar)


class CmppCancelRespPDU(PDU):
    body = {
        'success_id': Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I"
        super().__init__(grammar)


class CmppActiveTestPDU(HeaderPDU):
    pass


class CmppActiveTestRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3Ic"
        super().__init__(grammar)


class CmppFwdPDU(PDU):
    """
    ISMG -> ISMG
    """
    body = {
        'source_id': Param(type=str, size=6),
        'destination_id': Param(type=str, size=6),
        'nodes_count': Param(type=int, size=1),
        'msg_fwd_type': Param(type=int, size=1),
        'msg_id': Param(type=int, size=8),
        'pk_total': Param(type=int, size=1),
        'pk_number': Param(type=int, size=1),
        'registered_delivery': Param(type=int, size=1),
        'msg_level': Param(type=int, size=1),
        'service_id': Param(type=str, size=10),
        'fee_usertype': Param(type=int, size=1),
        'fee_terminal_id': Param(type=str, size=21),
        'fee_terminal_pseudo': Param(type=str, size=32),
        'fee_terminal_usertype': Param(type=int, size=1),
        'tp_pid': Param(type=int, size=1),
        'tp_udhi': Param(type=int, size=1),
        'msg_fmt': Param(type=int, size=1),
        'msg_src': Param(type=str, size=6),
        'fee_type': Param(type=str, size=2),
        'fee_code': Param(type=str, size=6),
        'valid_time': Param(type=str, size=17),
        'at_time': Param(type=str, size=17),
        'src_id': Param(type=str, size=21),
        'src_pseudo': Param(type=str, size=32),
        'src_usertype': Param(type=int, size=1),
        'src_type': Param(type=int, size=1),
        'dest_usr_tl': Param(type=int, size=1),
        'dest_id': Param(type=str, size=21),
        'dest_pseudo': Param(type=str, size=32),
        'dest_usertype': Param(type=int, size=1),
        'msg_length': Param(type=int, size=1),
        'msg_content': Param(type=str),
        'link_id': Param(type=str, size=20),
    }
    # MO或MT状态报告
    msg_content = {
        "msg_id": Param(type=int, size=8),
        "Stat": Param(type=str, size=7),
        "CMPP_DELIVER_time": Param(type=str, size=10),
        "CMPP_DELIVER_RESP_time": Param(type=str, size=10),
        "Dest_Id": Param(type=str, size=21),
        "Reserved": Param(type=str, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        try:
            if self.msg_content:
                self.msg_bytes = self.gen_msg_bytes()
        except AttributeError as e:
            pass
        self.msg_length = len(self.msg_bytes)
        grammar = f">3I6s6s2BQ4B10sB21s32s4B6s2s6s17s17s21s32s3B21s32s2B{self.msg_length}s20s"
        super().__init__(grammar)


class CmppFwdRespPDU(PDU):
    body = {
        "msg_id": Param(type=int, size=8),
        "pk_total": Param(type=int, size=1),
        "pk_number": Param(type=int, size=1),
        "result": Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQ2BI"
        super().__init__(grammar)




class CmppMtRoutePDU(PDU):
    """
    ISMG -> GNS
    """
    body = {
        "source_id": Param(type=str, size=6),
        "terminal_id": Param(type=str, size=21)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3I6s21s"
        super().__init__(grammar)


class CmppMtRouteRespPDU(PDU):
    body = {
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "start_id": Param(type=str, size=9),
        "end_id": Param(type=str, size=9),
        "area_code": Param(type=str, size=4),
        "result": Param(type=int, size=1),
        "user_type": Param(type=int, size=1),
        "time_stamp": Param(type=str, size=14),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I6s15sH9s9s4s2B14s"
        super().__init__(grammar)


class CmppMoRoutePDU(PDU):
    """
    ISMG -> GNS
    """
    body = {
        "source_id": Param(type=str, size=6),
        "sp_code": Param(type=str, size=21),
        "service_id": Param(type=str, size=10),
        "service_code": Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3I6s21s10sI"
        super().__init__(grammar)


class CmppMoRouteRespPDU(PDU):
    body = {
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "sp_id": Param(type=str, size=6),
        "sp_code": Param(type=str, size=21),
        "sp_acess_type": Param(type=int, size=1),
        "start_code": Param(type=int, size=4),
        "end_code": Param(type=int, size=4),
        "result": Param(type=int, size=1),
        "time_stamp": Param(type=str, size=14)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I6s15sH6s21sB2IB14s"
        super().__init__(grammar)


class CmppGetMtRoutePDU(PDU):
    """
    ISMG -> GNS
    """
    body = {
        "source_id": Param(type=str, size=6),
        "route_type": Param(type=str, size=4),
        "last_route_id": Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3I6s4si"
        super().__init__(grammar)


class CmppGetMtRouteRespPDU(PDU):
    body = {
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "start_id": Param(type=str, size=9),
        "end_id": Param(type=str, size=9),
        "area_code": Param(type=str, size=4),
        "result": Param(type=int, size=1),
        "user_type": Param(type=int, size=1),
        "route_total": Param(type=int, size=4),
        "route_number": Param(type=int, size=4),
        "time_stamp": Param(type=str, size=14),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I6s15sH9s9s4s2B2I14s"
        super().__init__(grammar)


class CmppGetMoRoutePDU(CmppGetMtRoutePDU):
    """
    ISMG -> GNS
    """
    pass


class CmppGetMoRouteRespPDU(PDU):
    body = {
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "sp_id": Param(type=str, size=6),
        "sp_code": Param(type=str, size=21),
        "sp_acess_type": Param(type=int, size=1),
        "service_id": Param(type=str, size=10),
        "start_code": Param(type=int, size=4),
        "end_code": Param(type=int, size=4),
        "result": Param(type=int, size=1),
        "route_total": Param(type=int, size=4),
        "route_number": Param(type=int, size=4),
        "time_stamp": Param(type=str, size=14)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I6s15sH6s21sB10s2IB2I14s"
        super().__init__(grammar)


class CmppMtRouteUpdatePDU(PDU):
    """
    ISMG -> GNS
    """
    body = {
        "update_type": Param(type=int, size=1),
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "start_id": Param(type=str, size=9),
        "end_id": Param(type=str, size=9),
        "area_code": Param(type=str, size=4),
        "user_type": Param(type=int, size=1),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IBI6s15sH9s9s4sB"
        super().__init__(grammar)


class CmppMtRouteUpdateRespPDU(PDU):
    body = {
        "result": Param(type=int, size=1),
        "route_id": Param(type=int, size=4),
        "time_stamp": Param(type=str, size=14),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IBI14s"
        super().__init__(grammar)


class CmppMoRouteUpdatePDU(PDU):
    """
    ISMG -> GNS
    """
    body = {
        "update_type": Param(type=int, size=1),
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "sp_id": Param(type=str, size=6),
        "sp_code": Param(type=str, size=21),
        "sp_acess_type": Param(type=int, size=1),
        "service_id": Param(type=str, size=10),
        "start_code": Param(type=int, size=4),
        "end_code": Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IBI6s15sH6s21sB10s2I"
        super().__init__(grammar)


class CmppMoRouteUpdateRespPDU(CmppMtRouteUpdateRespPDU):
    pass


class CmppPushMtRouteUpdatePDU(PDU):
    """
    GNS -> ISMG
    """
    body = {
        "update_type": Param(type=int, size=1),
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "start_id": Param(type=str, size=9),
        "end_id": Param(type=str, size=9),
        "area_code": Param(type=str, size=4),
        "user_type": Param(type=int, size=1),
        "time_stamp": Param(type=str, size=14),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IBI6s15sH9s9s4sB14s"
        super().__init__(grammar)


class CmppPushMtRouteUpdateRespPDU(PDU):
    body = {
        "result": Param(type=int, size=1),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IB"
        super().__init__(grammar)


class CmppPushMoRouteUpdatePDU(PDU):
    """
    GNS -> ISMG
    """
    body = {
        "update_type": Param(type=int, size=1),
        "route_id": Param(type=int, size=4),
        "destination_id": Param(type=str, size=6),
        "gateway_ip": Param(type=str, size=15),
        "gateway_port": Param(type=int, size=2),
        "sp_id": Param(type=str, size=6),
        "sp_code": Param(type=str, size=21),
        "sp_acess_type": Param(type=int, size=1),
        "service_id": Param(type=str, size=10),
        "start_code": Param(type=int, size=4),
        "end_code": Param(type=int, size=4),
        "time_stamp": Param(type=str, size=14)
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IBI6s15sH6s21sB10s2I14s"
        super().__init__(grammar)


class CmppPushMoRouteUpdateRespPDU(CmppPushMtRouteUpdateRespPDU):
    pass
