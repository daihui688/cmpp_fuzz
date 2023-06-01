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


class DeliverSMPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">LLLLBBB{len(self.source_addr) + 1}sBB{len(self.destination_addr) + 1}scBcccBcBcB{self.sm_length}s" \
                  + f"{len(self.optional_params)}s"
        super().__init__(grammar)
        self.service_type = None
        self.source_addr_ton = None
        self.source_addr_npi = None
        self.dest_addr_ton = None
        self.dest_addr_npi = None
        self.esm_class = None
        self.protocol_id = None
        self.priority_flag = None
        self.schedule_delivery_time = None
        self.validity_period = None
        self.registered_delivery = None
        self.replace_if_present_flag = None
        self.data_coding = None
        self.sm_default_msg_id = None
        self.short_message = None
        self.message_bytes = None

    def __str__(self):
        return super().__str__()[:-1] + f",source_addr={self.source_addr},destination_addr={self.destination_addr}"


class DeliverSMRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">LLLLc"
        super().__init__(grammar)
        # self.message_id = consts.NULL_BYTE

    def pack(self):
        data = self.struct.pack(self.command_length, self.command_id, self.command_status, self.sequence_number,
                                self.message_id)
        return data


class DataSMPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)

        message_bytes = self.gen_message_bytes()
        self.message_payload = message_bytes + b'\x1b\x3c\x54\x52\x49\x41\x4c\x1b\x3e'
        self.payload_length = len(self.message_payload)
        grammar = f">LLLLcBB{len(self.source_addr) + 1}sBB{len(self.destination_addr) + 1}scBBHH{self.payload_length}s"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.command_length, self.command_id, self.command_status, self.sequence_number,
                                self.service_type, self.source_addr_ton, self.source_addr_npi,
                                self.source_addr.encode() + b'\x00', self.dest_addr_ton, self.dest_addr_npi,
                                self.destination_addr.encode() + b'\x00', self.esm_class, self.registered_delivery,
                                self.data_coding, self.message_payload_tag, self.payload_length, self.message_payload)
        return data


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
        data = self.struct.pack(self.total_length, self.command_id, self.sequence_id,self.time.encode(),self.query_type,
                                self.query_code.encode(),self.reserve.encode())
        return data


class CmppQueryRespPDU(PDU):
    # params = {
    #     'message_id': Param(type=str, max=65),
    #     'final_date': Param(type=str, max=17),
    #     'message_state': Param(type=int, size=1),
    #     'error_code': Param(type=int, size=1),
    # }

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">LLLL{len(self.message_id)}sBBB"
        super().__init__(grammar)

    def __str__(self):
        return super().__str__() + f"message_id:{self.message_id}),final_date:{self.final_date}," + \
            f"message_state:{self.message_state},error_code:{self.error_code}"


class CancelSMPDU(PDU):
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

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        grammar = f">LLLLc{len(self.message_id) + 1}sBB{len(self.source_addr) + 1}sBB{len(self.destination_addr) + 1}s"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.command_length, self.command_id, self.command_status, self.sequence_number,
                                self.service_type, self.message_id.encode() + b'\x00',
                                self.source_addr_ton, self.source_addr_npi, self.source_addr.encode() + b'\x00',
                                self.dest_addr_ton, self.dest_addr_npi, self.destination_addr.encode() + b'\x00')
        return data


class CancelSMRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


class ReplaceSMPDU(PDU):
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

    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        self.message_bytes = self.gen_message_bytes()
        self.sm_length = len(self.message_bytes)
        grammar = f">LLLL{len(self.message_id) + 1}sBB{len(self.source_addr) + 1}sBBBBB{self.sm_length}s"
        super().__init__(grammar)

    def pack(self):
        data = self.struct.pack(self.command_length, self.command_id, self.command_status, self.sequence_number,
                                self.message_id.encode() + b'\x00', self.source_addr_ton, self.source_addr_npi,
                                self.source_addr.encode() + b'\x00', self.schedule_delivery_time, self.validity_period,
                                self.registered_delivery, self.sm_default_msg_id, self.sm_length, self.message_bytes)
        return data


class ReplaceSMRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


class EnquireLinkPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


class EnquireLinkRespPDU(PDU):
    def __init__(self, **kwargs):
        self._set_vals(kwargs)
        super().__init__()


if __name__ == '__main__':
    p = CmppConnectPDU()
