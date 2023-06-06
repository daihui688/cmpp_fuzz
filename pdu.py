import struct

import const
import command


class Param:
    def __init__(self, type, size=None):
        self.type = type
        self.size = size


class PDU:
    header = {
        "Total_Length": Param(type=int, size=4),
        "Command_Id": Param(type=int, size=4),
        "Sequence_Id": Param(type=int, size=4)
    }

    def __init__(self, grammar=">3I"):
        self.struct = struct.Struct(grammar)
        self.total_length = self.struct.size

    def _set_vals(self, d):
        for k, v in d.items():
            setattr(self, k, v)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id)
        return data

    def unpack(self, resp):
        return self.struct.unpack(resp)

    def gen_msg_bytes(self):
        try:
            return self.msg_content.encode(const.Msg_Fmt[self.msg_fmt])
        except Exception:
            return self.msg_content.encode('ascii')

    def __str__(self):
        command_id = command.get_command_name(self.command_id)
        return f"PDU(Total_Length:{self.total_length},Command_Id:{command_id},Sequence_Id:{self.sequence_id},"


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id,
                                self.source_addr.encode(), self.authenticator_source,
                                self.version, self.timestamp)
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.status,
                                self.authenticatorISMG,
                                self.version)
        return data

    def __str__(self):
        return super().__str__() + f"Status:{self.status})"


class CmppTerminatePDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


class CmppTerminateRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


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
        except AttributeError as e:
            pass
        self.msg_length = len(self.msg_bytes)
        grammar = f">3IQ4B10sB32s4B6s2s6s17s17s21sB32s2B{self.msg_length}s20s"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.msg_id, self.pk_total,
                                self.pk_number, self.registered_delivery, self.msg_level, self.service_id.encode(),
                                self.fee_usertype, self.fee_terminal_id.encode(), self.fee_terminal_type, self.tp_pid,
                                self.tp_udhi, self.msg_fmt, self.msg_src.encode(), self.fee_type.encode(),
                                self.fee_code.encode(), self.valid_time.encode(), self.at_time.encode(),
                                self.src_id.encode(), self.dest_usr_tl, self.dest_terminal_id.encode(),
                                self.dest_terminal_type, self.msg_length, self.msg_bytes, self.link_id.encode())
        return data


class CmppSubmitRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQI"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.msg_id, self.result)
        return data

    def __str__(self):
        return super().__str__() + f"Msg_Id:{self.msg_id}),Result:{self.result}"


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
        except AttributeError as e:
            pass
        self.msg_length = len(self.msg_bytes)
        grammar = f">3IQ21s10s3B32s3B{self.msg_length}s20s"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.msg_id,
                                self.dest_id.encode(),
                                self.service_id.encode(), self.tp_pid, self.tp_udhi, self.msg_fmt,
                                self.src_terminal_id.encode(), self.src_terminal_type,
                                self.registered_delivery, self.msg_length, self.msg_bytes, self.link_id.encode())
        return data


class CmppDeliverRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQI"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.msg_id, self.result)
        return data

    def __str__(self):
        return super().__str__() + f"Msg_Id:{self.msg_id}),Result:{self.result}"


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.time.encode(),
                                self.query_type,
                                self.query_code.encode(), self.reserve.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.time.encode(),
                                self.query_type,
                                self.query_code.encode(), self.mt_tl_msg, self.mt_tl_usr, self.mt_scs, self.mt_wt,
                                self.mt_fl, self.mo_scs, self.mo_wt, self.mo_fl)
        return data

    def __str__(self):
        return super().__str__() + ''


class CmppCancelPDU(PDU):
    body = {
        'msg_id': Param(type=int, size=8),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IQ"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.msg_id)
        return data


class CmppCancelRespPDU(PDU):
    body = {
        'success_id': Param(type=int, size=4),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">4I"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.success_id)
        return data


class CmppActiveTestPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


class CmppActiveTestRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3Ic"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.reserved.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id,
                                self.source_id.encode(), self.destination_id.encode(), self.nodes_count,
                                self.msg_fwd_type,
                                self.msg_id, self.pk_total, self.pk_number, self.registered_delivery, self.msg_level,
                                self.service_id.encode(), self.fee_usertype, self.fee_terminal_id.encode(),
                                self.fee_terminal_pseudo.encode(), self.fee_terminal_usertype, self.tp_pid,
                                self.tp_udhi, self.msg_fmt, self.msg_src.encode(), self.fee_type.encode(),
                                self.fee_code.encode(), self.valid_time.encode(), self.at_time.encode(),
                                self.src_id.encode(), self.src_pseudo.encode(), self.src_usertype, self.src_type,
                                self.dest_usr_tl, self.dest_id.encode(), self.dest_pseudo.encode(),
                                self.dest_usertype, self.msg_length, self.msg_bytes, self.link_id.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.msg_id, self.pk_total,
                                self.pk_number, self.result)
        return data

    def __str__(self):
        return super().__str__() + f"Msg_Id:{self.msg_id}),Result:{self.result}"


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.source_id.encode(),
                                self.terminal_id.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.start_id.encode(), self.end_id.encode(), self.area_code.encode(), self.result,
                                self.user_type, self.time_stamp.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.source_id.encode(),
                                self.sp_code.encode(), self.service_id.encode(), self.service_code)
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.sp_id.encode(), self.sp_code.encode(), self.sp_acess_type, self.start_code,
                                self.end_code, self.result, self.time_stamp.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.source_id.encode(),
                                self.route_type.encode(), self.last_route_id)
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.start_id.encode(), self.end_id.encode(), self.area_code.encode(), self.result,
                                self.user_type, self.route_total, self.route_number, self.time_stamp.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.sp_id.encode(), self.sp_code.encode(), self.sp_acess_type,
                                self.service_id.encode(),
                                self.start_code, self.end_code, self.result, self.route_total, self.route_number,
                                self.time_stamp.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.update_type, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.start_id.encode(), self.end_id.encode(), self.area_code.encode(), self.user_type)
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.result, self.route_id,
                                self.time_stamp.encode())
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.update_type, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.sp_id.encode(), self.sp_code.encode(), self.sp_acess_type,
                                self.service_id.encode(), self.start_code, self.end_code)
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.update_type, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.start_id.encode(), self.end_id.encode(), self.area_code.encode(), self.user_type,
                                self.time_stamp.encode())
        return data


class CmppPushMtRouteUpdateRespPDU(PDU):
    body = {
        "result": Param(type=int, size=1),
    }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">3IB"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.result)
        return data


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

    def pack(self):
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id, self.update_type, self.route_id,
                                self.destination_id.encode(), self.gateway_ip.encode(), self.gateway_port,
                                self.sp_id.encode(), self.sp_code.encode(), self.sp_acess_type,
                                self.service_id.encode(), self.start_code, self.end_code, self.time_stamp.encode())
        return data


class CmppPushMoRouteUpdateRespPDU(CmppPushMtRouteUpdateRespPDU):
    pass
