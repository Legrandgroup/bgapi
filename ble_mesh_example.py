import logging
import time
import bgapi.api
import threading
import sys
import struct
from binascii import hexlify

from bgapi.cmd_def import RESULT_CODE, ATTRIBUTE_CHANGE_REASON, ATTRIBUTE_STATUS_FLAGS, ATTRIBUTE_VALUE_TYPE

#PORT = "COM3"
PORT = "/dev/ttyACM0"

logger = None

class BleMeshNode(object):
    def __init__(self, port, baud, timeout=0.1, bgapi_handler=None):
        self._state=0
        self._state_lock = threading.Lock()       # This mutex protects access to attribute state
        self._modem_init_done = threading.Event()
        self._flash_erase_done = threading.Event()
        self._get_bt_address_done = threading.Event()
        if bgapi_handler is not None:
            self._bgapi=bgapi_handler
        else:
            self._bgapi=bgapi.api.BlueGigaAPI(port=port, callbacks=self, baud=baud, timeout=timeout)
        self._bgapi.start_daemon()
        self._logger = logging.getLogger("bgapi")
    
    def modem_reset(self, timeout=5):
        with self._state_lock:
            self._state=1
            self._modem_init_done.clear()
            self._bgapi.ble_cmd_system_reset(0)
        if not self._modem_init_done.wait(timeout):
            self._logger.error('Modem reset timed out')
            raise Exception('Modem reset timed out')
    
    def flash_erase(self, timeout=1):
        self._flash_erase_done.clear()
        self._bgapi.ble_cmd_flash_ps_erase_all()
        if not self._flash_erase_done.wait(timeout):
            self._logger.error('Flash erase timed out')
            raise Exception('Flash erase timed out')
    
    def get_bt_address(self, timeout=1):
        self._get_bt_address_done.clear()
        self._bgapi.ble_cmd_system_get_bt_address()
        if not self._get_bt_address_done.wait(timeout):
            self._logger.error('Get BT address timed out')
            #raise Exception('Get BT address timed out')
    
    def wait_provisioned(self, timeout=0):
        pass
    
    def ble_rsp_system_reset(self):
        self._logger.info("RSP-System Reset")
    
    def ble_evt_system_boot(self, major, minor, patch, build, bootloader, hw, hash):
        self._logger.info("EVT-System Boot - Version:%d.%d.%d.%d - Bootloader Version:%d - hw:%d - Version hash:%s" %
                    (major, minor, patch, build, bootloader, hw, hex(hash)))
        with self._state_lock:
            self._state=2
            self._modem_init_done.set()
    
    def ble_rsp_system_hello(self):
        self._logger.info("RSP-System Hello")

    def ble_rsp_system_address_get(self, address):
        self._logger.info("RSP-System Address Get - " + hexlify(address).decode('ascii').upper())

    def ble_rsp_system_get_bt_address(self, address):
        address = ':'.join([ '%02X' % ord(b) for b in address ])
        self._logger.info('RSP-Bt Address [%s]' % address)
        self._get_bt_address_done.set()

    def ble_rsp_system_reg_write(self, result):
        self._logger.info("RSP-System Register Write: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_reg_read(self, address, value):
        self._logger.info("RSP-System Register Read - Address:%02X - Value:%02X" % (address, value))

    def ble_rsp_system_get_counters(self, txok, txretry, rxok, rxfail, mbuf):
        self._logger.info("RSP-System Get Counters %d %d %d %d %d" % (txok, txretry, rxok, rxfail, mbuf))

    def ble_rsp_system_get_connections(self, maxconn):
        self._logger.info("RSP-System Get Connections - Maximum Connections:%d" % (maxconn))

    def ble_rsp_system_read_memory(self, address, data):
        self._logger.info("RSP-System Read Memory: %08x %s" % (address, data))

    def ble_rsp_system_get_info(self, major, minor, patch, build, ll_version, protocol_version, hw):
        self._logger.info("RSP-System Get Info: %d.%d.%d.%d, ll:%d, proto:%d, hw:%d" %
                    (major, minor, patch, build, ll_version, protocol_version, hw))

    def ble_rsp_system_endpoint_tx(self, result):
        self._logger.info("RSP-System Endpoint TX: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_append(self, result):
        self._logger.info("RSP-System Whitelist Append: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_remove(self, result):
        self._logger.info("RSP-System Whitelist Remove: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_clear(self):
        self._logger.info("RSP-System Whitelist Clear")

    def ble_rsp_system_endpoint_rx(self, result, data):
        self._logger.info("RSP-System Endpoint RX: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_system_endpoint_set_watermarks(self, result):
        self._logger.info("RSP-System Endpoing Set Watermark: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_ps_defrag(self):
        self._logger.info("RSP-Flash PS Defrag")

    def ble_rsp_flash_ps_dump(self):
        self._logger.info("RSP-Flash PS Dump")

    def ble_rsp_flash_ps_erase_all(self, result):
        self._logger.info('RSP-Flash PS Erase All [%s]' % (RESULT_CODE[result]))
        if (result==0):
            self._flash_erase_done.set()
        else:
            self._logger.error('Flash erase command failed')

    def ble_rsp_flash_ps_save(self, result):
        self._logger.info("RSP-Flash PS Save: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_ps_load(self, result, value):
        self._logger.info("RSP-Flash PS Load: [%s] - Value:%s" %  (RESULT_CODE[result], hexlify(value[::-1]).decode('ascii').upper()))

    def ble_rsp_flash_ps_erase(self):
        self._logger.info("RSP-Flash PS Erase")

    def ble_rsp_flash_erase_page(self, result):
        self._logger.info("RSP-Flash Erase Page: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_write_words(self):
        self._logger.info("RSP-Flash Write Words")

    def ble_rsp_attributes_write(self, result):
        self._logger.info("RSP-Attributes Write: [%s]" %  RESULT_CODE[result])

    def ble_rsp_attributes_read(self, handle, offset, result, value):
        self._logger.info("RSP-Attributes Read [%s] - Handle:%d - Offset:%d - Value:%s" %  (RESULT_CODE[result], handle, offset, hexlify(value[::-1]).decode('ascii').upper()))

    def ble_rsp_attributes_read_type(self, handle, result, value):
        self._logger.info("RSP-Attributes Read Type [%s] - Handle:%d Value:%s" % (RESULT_CODE[result], handle, hexlify(value[::-1]).decode('ascii').upper()))

    def ble_rsp_attributes_user_read_response(self):
        self._logger.info("RSP-Attributes User Read Response")

    def ble_rsp_attributes_user_write_response(self):
        self._logger.info("RSP-Attributes User Write Response")

    def ble_rsp_attributes_send(self, result):
        self._logger.info("RSP-Attributes Send [%s]", RESULT_CODE[result])

    def ble_rsp_connection_disconnect(self, connection, result):
        self._logger.info("RSP-Connection Disconnect - Connection:%d - [%s]" % (connection, RESULT_CODE[result]))

    def ble_rsp_connection_get_rssi(self, connection, rssi):
        self._logger.info("RSP-Connection Get RSSI: (%d, %d)" % (connection, rssi))

    def ble_rsp_connection_update(self, connection, result):
        self._logger.info("RSP-Connection Update: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_version_update(self, connection, result):
        self._logger.info("RSP-Connection Version Update: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_channel_map_get(self, connection, map):
        self._logger.info("RSP-Connection Channel Map Get: (%d)" % (connection))

    def ble_rsp_connection_channel_map_set(self, connection, result):
        self._logger.info("RSP-Connection Channel Map Set: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_features_get(self, connection, result):
        self._logger.info("RSP-Connection Features Get: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_get_status(self, connection):
        self._logger.info("RSP-Connection Get Status: (%d)" % (connection))

    def ble_rsp_connection_raw_tx(self, connection):
        self._logger.info("RSP-Connection Raw TX: (%d)" % (connection))

    def ble_rsp_attclient_find_by_type_value(self, connection, result):
        self._logger.info("RSP-Attribute Client Find By Type Value: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_by_group_type(self, connection, result):
        self._logger.info("RSP-Attribute Client Read By Group Type - Connection:%d - [%s]" % (connection, RESULT_CODE[result]))

    def ble_rsp_attclient_read_by_type(self, connection, result):
        self._logger.info("RSP-Attribute Client Read By Type: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_find_information(self, connection, result):
        self._logger.info("RSP-Attribute Client Find Information: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_by_handle(self, connection, result):
        self._logger.info("RSP-Attribute Client Read By Handle: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_attribute_write(self, connection, result):
        self._logger.info("RSP-Attribute Client Attribute Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_write_command(self, connection, result):
        self._logger.info("RSP-Attribute Client Write Command: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_indicate_confirm(self, result):
        self._logger.info("RSP-Attribute Client Indicate Confirm: [%s]" % RESULT_CODE[result])

    def ble_rsp_attclient_read_long(self, connection, result):
        self._logger.info("RSP-Attribute Client Read Long: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_prepare_write(self, connection, result):
        self._logger.info("RSP-Attribute Client Prepare Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_execute_write(self, connection, result):
        self._logger.info("RSP-Attribute Client Execute Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_multiple(self, connection, result):
        self._logger.info("RSP-Attribute Client Read Multiple: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_sm_encrypt_start(self, handle, result):
        self._logger.info("RSP-SM Encryption Start: [%s] (%d)" % (RESULT_CODE[result], handle))

    def ble_rsp_sm_set_bondable_mode(self):
        self._logger.info("RSP-SM Bondable Mode")

    def ble_rsp_sm_delete_bonding(self, result):
        self._logger.info("RSP-SM Delete Bonding: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_sm_set_parameters(self):
        self._logger.info("RSP-SM Set Parameters")

    def ble_rsp_sm_passkey_entry(self, result):
        self._logger.info("RSP-SM Passkey Entry: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_sm_get_bonds(self, bonds):
        self._logger.info("RSP-SM Get Bonds")

    def ble_rsp_sm_set_oob_data(self):
        self._logger.info("RSP-SM Set OOB Data")

    def ble_rsp_gap_set_privacy_flags(self):
        self._logger.info("RSP-GAP Set Privacy Flags")

    def ble_rsp_gap_set_mode(self, result):
        self._logger.info("RSP-GAP Set Mode: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_discover(self, result):
        self._logger.info("RSP-GAP Discover: [%s]" % RESULT_CODE[result])

    def ble_rsp_gap_connect_direct(self, result, connection_handle):
        self._logger.info("RSP-GAP Connect Direct: [%s] (%d)" % (RESULT_CODE[result], connection_handle))

    def ble_rsp_gap_end_procedure(self, result):
        self._logger.info("RSP-GAP End Procedure: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_connect_selective(self, result, connection_handle):
        self._logger.info("RSP-GAP Connect Selective: [%s] (%d)" % (RESULT_CODE[result], connection_handle))

    def ble_rsp_gap_set_filtering(self, result):
        self._logger.info("RSP-GAP Set Filtering: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_scan_parameters(self, result):
        self._logger.info("RSP-GAP Set Scan Parameters: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_adv_parameters(self, result):
        self._logger.info("RSP-GAP Set Advertisement Parameters: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_adv_data(self, result):
        self._logger.info("RSP-GAP Set Advertisement Data: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_directed_connectable_mode(self, result):
        self._logger.info("RSP-GAP Set Directed Connectable Mode: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_irq(self, result):
        self._logger.info("RSP-Hardware IO Port Config IRQ: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_set_soft_timer(self, result):
        self._logger.info("RSP-Hardware Set Soft Timer: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_adc_read(self, result):
        self._logger.info("RSP-Hardware ADC Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_direction(self, result):
        self._logger.info("RSP-Hardware IO Port Config Direction: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_function(self, result):
        self._logger.info("RSP-Hardware IO Port Config Function: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_pull(self, result):
        self._logger.info("RSP-Hardware IO Port Config Pullup: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_write(self, result):
        self._logger.info("RSP-Hardware IO Port Write: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_read(self, result, port, data):
        self._logger.info("RSP-Hardware IO Port Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_spi_config(self, result):
        self._logger.info("RSP-Hardware SPI Config: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_spi_transfer(self, result, channel, data):
        self._logger.info("RSP-Hardware SPI Transfer: [%s] (%d)" % (RESULT_CODE[result], channel))

    def ble_rsp_hardware_i2c_read(self, result, data):
        self._logger.info("RSP-Hardware I2C Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_i2c_write(self, written):
        self._logger.info("RSP-Hardware I2C Write: ")

    def ble_rsp_hardware_set_txpower(self):
        self._logger.info("RSP-Hardware Set TX Power")

    def ble_rsp_hardware_timer_comparator(self, result):
        self._logger.info("RSP-Hardware Timer Comparator: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_test_phy_tx(self):
        self._logger.info("RSP-Test Phy TX")

    def ble_rsp_test_phy_rx(self):
        self._logger.info("RSP-Test Phy RX")

    def ble_rsp_test_phy_end(self, counter):
        self._logger.info("RSP-Test Phy End: %d" % (counter))

    def ble_rsp_test_phy_reset(self):
        self._logger.info("RSP-Test Phy Reset")

    def ble_rsp_test_get_channel_map(self, channel_map):
        self._logger.info("RSP-Test Get Channel Map")

    def ble_rsp_test_debug(self, output):
        self._logger.info("RSP-Test Debug")

    def ble_evt_mesh_node_initialized(self, provisioned, address, ivi):
        self._logger.info("EVT-Mesh Node Initialized - Provisioned:%d - Primary Element Unicast Address:%d - IV index:%d" %
                    (provisioned, address, ivi))
    
    def ble_evt_mesh_node_provisioned(self, iv_index, address):
        self._logger.info("EVT-Mesh Node Provisioned - IV index:%d - My primary address:%04x" % (iv_index, address))
    
    def ble_evt_mesh_node_provisioning_started(self, result):
        self._logger.info("EVT-Mesh Node Provisioning Started - Result:%s" % (RESULT_CODE[result]))
    
    def ble_evt_mesh_node_key_added(self, type, index, netkey_index):
        if type == 0x00:
            key_type_str='Network'
            netkey_index_str = ''
        else:
            netkey_index_str = " - Netkey Index:%d" % (netkey_index)
            if type == 0x01:
                key_type_str='Application'
            else:
                self._logger.error('Unknown key type in event: %d', type)
                key_type_str='Unknown'
        self._logger.info("EVT-Mesh Node Key Added - Type:%s - Index:%d" % (key_type_str, index) + netkey_index_str)
    
    def ble_evt_mesh_node_model_config_changed(self, mesh_node_config_state, element_address, vendor_id, model_id):
        if mesh_node_config_state == 0x00:
            config_state_str='Model application key bindings'
        elif mesh_node_config_state == 0x01:
            config_state_str='Model publication parameters'
        elif mesh_node_config_state == 0x02:
            config_state_str='Model subscription list'
        else:
            config_state_str='Unknown'
            self._logger.error('Unknown Mesh Node Config State: %02X' % (mesh_node_config_state))
        self._logger.info("EVT-Mesh Node Model Config Changed - Config State:%s - Element Address:%04X - Vendor ID:%02X - Model ID:%02X" % (config_state_str, element_address, vendor_id, model_id))
    
    def ble_evt_mesh_generic_server_client_request(self, model_id, elem_index, client_address, server_address, appkey_index, transition, delay, flags, type, value):
        if transition != 0:
            transition_str=' - Transition time:%dms' % (transition, )
        else:
            transition_str=''
        if delay != 0:
            delay_str=' - Delay:%dms' % (delay, )
        else:
            delay_str=''
        flags_str=''
        if flags & 1:
            flags_str+='Nonrelayed'
        if flags & 2:
            if flags!='':
                flags_str+='|'
            flags_str+='Response required'
        if flags_str != '':
            flags_str = ' - Flags:[' + flags_str + ']'
        if type != 0x00:
            type_str = ' - Type:%02X' % (type, )
        else:
            type_str = ''
        self._logger.info("EVT-Mesh Generic Server Client Request - Server Model ID:%04X - Element Index:%d" % (model_id, elem_index) +
                    " - Client Address:%04X - Server Address:%04X - Application Key Index:%d" % (client_address, server_address, appkey_index) +
                    transition_str +
                    delay_str +
                    flags_str +
                    type_str +
                    " - Value:%s" % (hexlify(value[::-1]).decode('ascii').upper(), ))
    
    def ble_evt_mesh_generic_client_server_status(self, model_id, elem_index, client_address, server_address, remaining, flags, type, value):
        flags_str=''
        if flags & 1:
            flags_str+='Nonrelayed'
        if flags_str != '':
            flags_str = ' - Flags:[' + flags_str + ']'
        self._logger.info("EVT-Mesh Generic Client Server Status - Server Model ID:%04X - Element Index:%d" % (model_id, elem_index) +
                          " - Client Address:%04X - Server Address:%04X - Remaining:%dms" % (client_address, server_address, remaining) +
                          flags_str +
                          " - Type:%02X - Value:%s" % (type, hexlify(value[::-1]).decode('ascii').upper()))
    
    def ble_evt_system_debug(self, data):
        self._logger.info("EVT-System Debug:", data)

    def ble_evt_system_endpoint_watermark_rx(self, endpoint, data):
        self._logger.info("EVT-System Endpoint Watermark RX: %d" % (endpoint))

    def ble_evt_system_endpoint_watermark_tx(self, endpoint, data):
        self._logger.info("EVT-System Endpoint Watermark TX: %d" % (endpoint))

    def ble_evt_system_script_failure(self, address, reason):
        self._logger.info("EVT-System Script Failure")

    def ble_evt_system_no_license_key(self):
        self._logger.info("EVT-System No License Key")

    def ble_evt_flash_ps_key(self, key, value):
        self._logger.info("EVT-Flash PS Key - Key:%04x - Value:%s" % (key, hexlify(value).decode('ascii').upper()))

    def ble_evt_attributes_value(self, connection, reason, handle, offset, value):
        self._logger.info("EVT-Attributes Value - Connection:%d - Reason:[%s] - Handle:%d - Offset:%d - " % (connection, ATTRIBUTE_CHANGE_REASON[reason], handle, offset) + \
            "Value:%s" % (hexlify(value).decode('ascii').upper(), ))

    def ble_evt_attributes_user_read_request(self, connection, handle, offset, maxsize):
        self._logger.info("EVT-Attributes User Read Request")

    def ble_evt_attributes_status(self, handle, flags):
        self._logger.info("EVT-Attributes Status - Handle:%d - Flags:[%s]" % (handle, ATTRIBUTE_STATUS_FLAGS[flags]))

    def ble_evt_connection_opened(self, address, address_type, master, connection, bonding, advertiser):
        result = address[::-1]
        result = ':'.join([ '%02X' % ord(b) for b in result ])
        self._logger.info("EVT-Connection Opened - Address:[%s] - " % (result, ) +
                    "Address Type:%d - Master:%d - Connection:%d - Bonding:%d - Advertiser:%d" % (address_type, master, connection, bonding, advertiser))

    def ble_evt_connection_closed(self, reason, connection):
        self._logger.info("EVT-Connection Closed - Reason:%s - Connection:%d " % (RESULT_CODE[reason], connection))

    def ble_evt_gatt_server_user_write_request(self, connection, characteristic, att_opcode, offset, value):
        self._logger.info("EVT-GATT Server User Write Request - Connection:%s - Characteristic:%04X - Opcode:%02x - Offset:%d - Value:%s" % (connection, characteristic, att_opcode, offset, hexlify(value).decode('ascii').upper()))

    def ble_evt_connection_status(self, connection, flags, address, address_type, conn_interval, timeout, latency, bonding):
        self._logger.info("EVT-Connection Status - Handle:%d - Flags:%02X - " % (connection, flags) +
                    "Address:%s - " % (hexlify(address[::-1]).decode('ascii').upper(), ) +
                    "Address Type:%d - Interval:%d - Timeout:%d - Latency:%d - Bonding:%d" % (address_type, conn_interval, timeout, latency, bonding))

    def ble_evt_connection_version_ind(self, connection, vers_nr, comp_id, sub_vers_nr):
        self._logger.info("EVT-Connection Version Ind")

    def ble_evt_connection_feature_ind(self, connection, features):
        self._logger.info("EVT-Connection Feature Ind")

    def ble_evt_connection_raw_rx(self, connection, data):
        self._logger.info("EVT-Connection Raw RX")

    def ble_evt_connection_disconnected(self, connection, reason):
        self._logger.info("EVT-Connection Disconnected - Connection:%d - Reason:%s" % (connection, RESULT_CODE[reason]))

    def ble_evt_attclient_indicated(self, connection, attrhandle):
        self._logger.info("EVT-Attribute Client Indicated - Connection:%d - Attribute Handle:%d" % (connection, attrhandle))

    def ble_evt_attclient_procedure_completed(self, connection, result, chrhandle):
        self._logger.info("EVT-Attribute Client Procedure Completed - Connection:%d - Result:[%s] - End Characteristic Handle:%d" %
                    (connection, RESULT_CODE[result], chrhandle))

    def ble_evt_attclient_group_found(self, connection, start, end, uuid):
        self._logger.info("EVT-Attribute Client Group Found - Connection:%d - Start Handle:%d - End Handle:%d - " % (connection, start, end) +
                    "UUID:" + hexlify(uuid[::-1]).decode('ascii').upper())

    def ble_evt_attclient_attribute_found(self, connection, chrdecl, value, properties, uuid):
        self._logger.info("EVT-Attribute Client Attribute Found")

    def ble_evt_attclient_find_information_found(self, connection, chrhandle, uuid):
        self._logger.info("EVT-Attribute Client Find Information Found - Connection:%d - Handle:%d - " % (connection, chrhandle) +
                    "UUID:" + hexlify(uuid[::-1]).decode('ascii').upper())

    def ble_evt_attclient_attribute_value(self, connection, atthandle, type, value):
        self._logger.info("EVT-Attribute Client Attribute Value - Connection:%d - Handle:%d - Type:%d - Value:%s" %
                    (connection, atthandle, type, hexlify(value).decode('ascii').upper()))

    def ble_evt_attclient_read_multiple_response(self, connection, handles):
        self._logger.info("EVT-Attribute Client Read Multiple Response")

    def ble_evt_sm_smp_data(self, handle, packet, data):
        self._logger.info("EVT-SM SMP Data")

    def ble_evt_sm_bonding_fail(self, handle, result):
        self._logger.info("EVT-SM Bonding Fail: [%s]" % (RESULT_CODE[result]))

    def ble_evt_sm_passkey_display(self, handle, passkey):
        self._logger.info("EVT-SM Passkey Display")

    def ble_evt_sm_passkey_request(self, handle):
        self._logger.info("EVT-SM Passkey Request")

    def ble_evt_sm_bond_status(self, bond, keysize, mitm, keys):
        self._logger.info("EVT-SM Bond Status - Bond:%d - Key Size:%d - MITM:%d - Keys Used Mask:%02X" %
                    (bond, keysize, mitm, keys))

    def ble_evt_gap_scan_response(self, rssi, packet_type, sender, address_type, bond, data):
        self._logger.info("EVT-GAP Scan Response - RSSI:%d - Packet Type:%d - " % (rssi, packet_type) +
                    "Sender:%02x:%02x:%02x:%02x:%02x:%02x - " % struct.unpack('BBBBBB', sender[::-1]) +
                    "Address Type:%d - Bond:%d - Data:" % (address_type, bond) +
                    hexlify(data).decode('ascii').upper())

    def ble_evt_gap_mode_changed(self, discover, connect):
        self._logger.info("EVT-GAP Mode Changed")

    def ble_evt_hardware_io_port_status(self, timestamp, port, irq, state):
        self._logger.info("EVT-Hardware IO Port Status")

    def ble_evt_hardware_soft_timer(self, handle):
        self._logger.info("EVT-Hardware Soft Timer")

    def ble_evt_hardware_adc_result(self, input, value):
        self._logger.info("EVT-Hardware ADC Result")
    
    
def example_ble_mesh_node():
    term = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(PORT + ': %(asctime)s - %(name)s - %(levelname)s - %(message)s')
    term.setFormatter(formatter)
    api_logger = logging.getLogger("bgapi")
    api_logger.addHandler(term)
    api_logger.setLevel(level=logging.DEBUG)
    
    logger=api_logger
    
    btmesh=BleMeshNode(port=PORT, baud=57600)
    btmesh.flash_erase()
    btmesh.modem_reset()
    btmesh.get_bt_address()
    
    btmesh._bgapi.ble_cmd_gatt_server_write_attribute_value(11, 0, 'fake node') # see app.c#L110 gattdb_device_name==11
    time.sleep(1)
    btmesh._bgapi.ble_cmd_mesh_node_set_adv_event_filter(0,'') # see main.c#L284    (was 0x07)
    time.sleep(1)
    # Should initialize LEDs then, run mesh_node_init() as done below
    btmesh._bgapi.ble_cmd_mesh_node_init()
    time.sleep(1)
    # After evt_mesh_node_initialized_id,
    #btmesh._bgapi.ble_cmd_mesh_proxy_init() # Here?
    #btmesh._bgapi.ble_cmd_mesh_proxy_server_init() # see app.c#L395
    btmesh._bgapi.ble_cmd_mesh_generic_server_init()
    time.sleep(1)
    btmesh._bgapi.ble_cmd_mesh_generic_client_init()
    time.sleep(1)
    # Then run gecko_cmd_mesh_node_start_unprov_beaconing(0x3) as done below
    btmesh._bgapi.ble_cmd_mesh_node_start_unprov_beaconing(1 | 2)
    logger.info('Waiting to be provisioned...')
    btmesh.wait_provisioned(timeout=0)
    logger.info('We have just been provisioned!')
    logger.info('Loop sending commands in 120s')
    time.sleep(30)
    logger.info('Loop sending commands in 90s')
    time.sleep(30)
    logger.info('Loop sending commands in 60s')
    time.sleep(30)
    logger.info('Loop sending commands in 30s')
    time.sleep(30)
    time.sleep(5)
    logger.info('Loop sending commands')
    for i in range(0, 5):
        btmesh._bgapi.ble_cmd_mesh_generic_client_publish(0x1001, 0, i, 1, 0, 0, 0, struct.pack('<B', i%2))
        time.sleep(15)

    # Will get evt_mesh_node_provisioning_started event
    # Allows to blink LEDs to show start of provisionning
    # Will then get either gecko_evt_mesh_node_provisioned_id or gecko_evt_mesh_node_provisioning_failed_id event
    btmesh._bgapi.t.join()

    
    logger.info('Execution finished')

if __name__ == "__main__":
    example_ble_mesh_node()
    time.sleep(0.5)  # Give it a moment for the responses to come back and get logged

