ISMG_HOST = "127.0.0.1"
ISMG_PORT = 7892
SOURCE_ADDR = "901234"
VERSION = 0x30
SHARED_SECRET = "1234"
SEQUENCE_ID = 1
SERVICE_ID = "sms0792001"
SOURCE_ID= '079210'
DESTINATION_ID = '079220'
SRC_ID = "+8618279230916"
TERMINAL_ID = "+8613520376620"
GATEWAY_IP = "10.1.2.43"
GATEWAY_PORT = 7890
FUZZ_COMMAND = ["CMPP_SUBMIT","CMPP_DELIVER_RESP","CMPP_QUERY","CMPP_CANCEL",
                "CMPP_ACTIVE_TEST","CMPP_FWD","CMPP_MT_ROUTE","CMPP_MO_ROUTE","CMPP_GET_MT_ROUTE","CMPP_GET_MO_ROUTE",
                "CMPP_MT_ROUTE_UPDATE","CMPP_MO_ROUTE_UPDATE","CMPP_PUSH_MT_ROUTE_UPDATE","CMPP_PUSH_MO_ROUTE_UPDATE"]
