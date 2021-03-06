from __future__ import absolute_import
import threading
import struct
import serial
import logging
import sys
import traceback

from binascii import hexlify
from .cmd_def import RESULT_CODE, ATTRIBUTE_CHANGE_REASON, ATTRIBUTE_STATUS_FLAGS, ATTRIBUTE_VALUE_TYPE

logger = logging.getLogger("bgapi")

MAX_BGAPI_PACKET_SIZE = 3 + 2048

def hexlify_nice(data):
    if sys.version_info >= (3, ):
        return ' '.join([ '%02X' % b for b in data ])
    else:
        return ' '.join([ '%02X' % ord(b) for b in data ])

class BlueGigaAPI(object):
    def __init__(self, port, callbacks=None, baud=115200, timeout=1):
        self._serial = serial.Serial(port=port, baudrate=baud, timeout=timeout)
        self._serial.flushInput()
        self._serial.flushOutput()
        self.rx_buffer = b''
        self._packet_size = 4
        self._timeout = timeout
        if not callbacks:
            self._callbacks = BlueGigaCallbacks()
        else:
            self._callbacks = callbacks

    def _run(self):
        self.rx_buffer = b''
        while (self._continue):
            self.poll_serial()
        self._serial.close()

    def poll_serial(self, max_read_len=MAX_BGAPI_PACKET_SIZE):
        self.rx_buffer += self._serial.read(min(self._packet_size - len(self.rx_buffer), max_read_len))
        while len(self.rx_buffer) >= self._packet_size:
            self._packet_size = 4 + (struct.unpack('>H', self.rx_buffer[:2])[0] & 0x7FF)
            if len(self.rx_buffer) < self._packet_size:
                break
            packet, self.rx_buffer = self.rx_buffer[:self._packet_size], self.rx_buffer[self._packet_size:]
            self._packet_size = 4
            
            try:
                self.parse_bgapi_packet(packet)
            except Exception as e:
                logger.error('Error parsing bgapi packet')
                ex_type, ex, tb = sys.exc_info()
                traceback.print_tb(tb)
                raise e

    def start_daemon(self):
        """
        Initiates a thread which manages all traffic received from serial
        and dispatches it to the appropriate callback
        """
        self._continue = True
        self.t = threading.Thread(target=self._run, args=())
        self.t.setDaemon(True)
        self.t.start()

    def stop_daemon(self):
        """
        Stops the thread which is monitoring the serial port for incoming
        traffic from the device.
        :return:
        """
        self._continue = False
        self.t.join(self._timeout)

    def daemon_running(self):
        return self._continue

    def send_command(self, packet_class, packet_method, payload=b'', packet_lolen=0x00):
        """
        It is easier to use the ble_cmd methods, use this if you know how to compose your own BGAPI packets.
        """
        packet_hilen = 0x20
        cmd = struct.pack('BBBB', packet_hilen, packet_lolen, packet_class, packet_method) + payload
        logger.debug('=>[ ' + hexlify_nice(cmd) + ' ]')
        self._serial.write(cmd)

    def ble_cmd_system_reset(self, boot_in_dfu):
        self.send_command(0x01, 0x01, struct.pack('<B', boot_in_dfu), 0x01)
    def ble_cmd_system_hello(self):
        self.send_command(0x01, 0x00)
    def ble_cmd_system_get_bt_address(self):
        self.send_command(0x01, 0x03)
    def ble_cmd_mesh_node_init(self):
        self.send_command(0x14, 0x00)
    def ble_cmd_mesh_node_start_unprov_beaconing(self, bearer):
        self.send_command(0x14, 0x01, struct.pack('<B', bearer), 0x01)
    def ble_cmd_mesh_node_set_adv_event_filter(self, mask, gap_data_type):
        self.send_command(0x14, 0x08, struct.pack('<HB' + str(len(gap_data_type)) + 's', mask, len(gap_data_type), gap_data_type), 0x03)
    def ble_cmd_mesh_generic_server_init(self):
        self.send_command(0x1f, 0x04)
    def ble_cmd_mesh_generic_server_publish(self, model_id, elem_index, type):
        self.send_command(0x1f, 0x02, struct.pack('<HHB', model_id, elem_index, type), 0x05)
    def ble_cmd_mesh_generic_client_init(self):
        self.send_command(0x1e, 0x04)
    def ble_cmd_mesh_generic_client_publish(self, model_id, elem_index, tid, transition, delay, flags, type, parameter):
        self.send_command(0x1e, 0x02, struct.pack('<HHBIHHBB' + str(len(parameter)) + 's', model_id, elem_index, tid, transition, delay, flags, type, len(parameter), parameter), 0x0f)
    def ble_cmd_gatt_server_write_attribute_value(self, attribute, offset, value):
        self.send_command(0x0a, 0x02, struct.pack('<HHB' + str(len(value)) + 's', attribute, offset, len(value), value), 0x05)
    def ble_cmd_flash_ps_dump(self):
        self.send_command(0x0d, 0x00)
    def ble_cmd_flash_ps_erase_all(self):
        self.send_command(0x0d, 0x01)
    def ble_cmd_flash_ps_save(self, key, value):
        self.send_command(0x0d, 0x02, struct.pack('<HB' + str(len(value)) + 's', key, len(value), value))
    def ble_cmd_flash_ps_load(self, key):
        self.send_command(0x0d, 0x03, struct.pack('<H', key), 0x02)
    def ble_cmd_flash_ps_erase(self, key):
        self.send_command(0x0d, 0x04, struct.pack('<H', key))
    def ble_cmd_flash_erase_page(self, page):
        self.send_command(1, 6, struct.pack('<B', page))
    def ble_cmd_flash_write_words(self, address, words):
        self.send_command(1, 7, struct.pack('<HB' + str(len(words)) + 's', address, len(words), words))
    def ble_cmd_attributes_write(self, handle, offset, value):
        self.send_command(2, 0, struct.pack('<HBB' + str(len(value)) + 's', handle, offset, len(value), value))
    def ble_cmd_attributes_read(self, handle, offset):
        self.send_command(2, 1, struct.pack('<HH', handle, offset))
    def ble_cmd_attributes_read_type(self, handle):
        self.send_command(2, 2, struct.pack('<H', handle))
    def ble_cmd_attributes_user_read_response(self, connection, att_error, value):
        self.send_command(2, 3, struct.pack('<BBB' + str(len(value)) + 's', connection, att_error, len(value), value))
    def ble_cmd_attributes_user_write_response(self, connection, att_error):
        self.send_command(2, 4, struct.pack('<BB', connection, att_error))
    def ble_cmd_attributes_send(self, connection, handle, value):
        self.send_command(2, 5, struct.pack('<BHB' + str(len(value)) + 's', connection, handle, len(value), value))
    def ble_cmd_connection_disconnect(self, connection):
        self.send_command(3, 0, struct.pack('<B', connection))
    def ble_cmd_connection_get_rssi(self, connection):
        self.send_command(3, 1, struct.pack('<B', connection))
    def ble_cmd_connection_update(self, connection, interval_min, interval_max, latency, timeout):
        self.send_command(3, 2, struct.pack('<BHHHH', connection, interval_min, interval_max, latency, timeout))
    def ble_cmd_connection_version_update(self, connection):
        self.send_command(3, 3, struct.pack('<B', connection))
    def ble_cmd_connection_channel_map_get(self, connection):
        self.send_command(3, 4, struct.pack('<B', connection))
    def ble_cmd_connection_channel_map_set(self, connection, map):
        self.send_command(3, 5, struct.pack('<BB' + str(len(map)) + 's', connection, len(map), map))
    def ble_cmd_connection_features_get(self, connection):
        self.send_command(3, 6, struct.pack('<B', connection))
    def ble_cmd_connection_get_status(self, connection):
        self.send_command(3, 7, struct.pack('<B', connection))
    def ble_cmd_connection_raw_tx(self, connection, data):
        self.send_command(3, 8, struct.pack('<BB' + str(len(data)) + 's', connection, len(data), data))
    def ble_cmd_attclient_find_by_type_value(self, connection, start, end, uuid, value):
        self.send_command(4, 0, struct.pack('<BHHHB' + str(len(value)) + 's', connection, start, end, uuid, len(value), value))
    def ble_cmd_attclient_read_by_group_type(self, connection, start, end, uuid): # =>[ 00 08 04 01 00 01 00 FF FF 02 00 28 ]
        self.send_command(4, 1, struct.pack('<BHHB' + str(len(uuid)) + 's', connection, start, end, len(uuid), uuid))
    def ble_cmd_attclient_read_by_type(self, connection, start, end, uuid):
        self.send_command(4, 2, struct.pack('<BHHB' + str(len(uuid)) + 's', connection, start, end, len(uuid), uuid))
    def ble_cmd_attclient_find_information(self, connection, start, end):
        self.send_command(4, 3, struct.pack('<BHH', connection, start, end))
    def ble_cmd_attclient_read_by_handle(self, connection, chrhandle):
        self.send_command(4, 4, struct.pack('<BH', connection, chrhandle))
    def ble_cmd_attclient_attribute_write(self, connection, atthandle, data):
        self.send_command(4, 5, struct.pack('<BHB' + str(len(data)) + 's', connection, atthandle, len(data), data))
    def ble_cmd_attclient_write_command(self, connection, atthandle, data):
        self.send_command(4, 6, struct.pack('<BHB' + str(len(data)) + 's', connection, atthandle, len(data), data))
    def ble_cmd_attclient_indicate_confirm(self, connection):
        self.send_command(4, 7, struct.pack('<B', connection))
    def ble_cmd_attclient_read_long(self, connection, chrhandle):
        self.send_command(4, 8, struct.pack('<BH', connection, chrhandle))
    def ble_cmd_attclient_prepare_write(self, connection, atthandle, offset, data):
        self.send_command(4, 9, struct.pack('<BHHB' + str(len(data)) + 's', connection, atthandle, offset, len(data), data))
    def ble_cmd_attclient_execute_write(self, connection, commit):
        self.send_command(4, 10, struct.pack('<BB', connection, commit))
    def ble_cmd_attclient_read_multiple(self, connection, handles):
        self.send_command(4, 11, struct.pack('<BB' + str(len(handles)) + 's', connection, len(handles), handles))
    def ble_cmd_sm_encrypt_start(self, handle, bonding):
        self.send_command(5, 0, struct.pack('<BB', handle, bonding))
    def ble_cmd_sm_set_bondable_mode(self, bondable):
        self.send_command(5, 1, struct.pack('<B', bondable))
    def ble_cmd_sm_delete_bonding(self, handle):
        self.send_command(5, 2, struct.pack('<B', handle))
    def ble_cmd_sm_set_parameters(self, mitm, min_key_size, io_capabilities):
        self.send_command(5, 3, struct.pack('<BBB', mitm, min_key_size, io_capabilities))
    def ble_cmd_sm_passkey_entry(self, handle, passkey):
        self.send_command(5, 4, struct.pack('<BI', handle, passkey))
    def ble_cmd_sm_get_bonds(self):
        self.send_command(5, 5)
    def ble_cmd_sm_set_oob_data(self, oob):
        self.send_command(5, 6, struct.pack('<B' + str(len(oob)) + 's', len(oob), oob))
    def ble_cmd_gap_set_privacy_flags(self, peripheral_privacy, central_privacy):
        self.send_command(6, 0, struct.pack('<BB', peripheral_privacy, central_privacy))
    def ble_cmd_gap_set_mode(self, discover, connect):
        self.send_command(6, 1, struct.pack('<BB', discover, connect))
    def ble_cmd_gap_discover(self, mode):
        self.send_command(6, 2, struct.pack('<B', mode))
    def ble_cmd_gap_connect_direct(self, address, addr_type, conn_interval_min, conn_interval_max, timeout, latency):
        self.send_command(6, 3, struct.pack('<6sBHHHH', address, addr_type, conn_interval_min, conn_interval_max, timeout, latency))
    def ble_cmd_gap_end_procedure(self):
        self.send_command(6, 4)
    def ble_cmd_gap_connect_selective(self, conn_interval_min, conn_interval_max, timeout, latency):
        self.send_command(6, 5, struct.pack('<HHHH', conn_interval_min, conn_interval_max, timeout, latency))
    def ble_cmd_gap_set_filtering(self, scan_policy, adv_policy, scan_duplicate_filtering):
        self.send_command(6, 6, struct.pack('<BBB', scan_policy, adv_policy, scan_duplicate_filtering))
    def ble_cmd_gap_set_scan_parameters(self, scan_interval, scan_window, active):
        self.send_command(6, 7, struct.pack('<HHB', scan_interval, scan_window, active))
    def ble_cmd_gap_set_adv_parameters(self, adv_interval_min, adv_interval_max, adv_channels):
        self.send_command(6, 8, struct.pack('<HHB', adv_interval_min, adv_interval_max, adv_channels))
    def ble_cmd_gap_set_adv_data(self, set_scanrsp, adv_data):
        self.send_command(6, 9, struct.pack('<BB' + str(len(adv_data)) + 's',  set_scanrsp, len(adv_data), adv_data))
    def ble_cmd_gap_set_directed_connectable_mode(self, address, addr_type):
        self.send_command(6, 10, address + struct.pack('<B', addr_type))
    def ble_cmd_hardware_io_port_config_irq(self, port, enable_bits, falling_edge):
        self.send_command(7, 0, struct.pack('<BBB', port, enable_bits, falling_edge))
    def ble_cmd_hardware_set_soft_timer(self, time, handle, single_shot):
        self.send_command(7, 1, struct.pack('<IBB', time, handle, single_shot))
    def ble_cmd_hardware_adc_read(self, input, decimation, reference_selection):
        self.send_command(7, 2, struct.pack('<BBB', input, decimation, reference_selection))
    def ble_cmd_hardware_io_port_config_direction(self, port, direction):
        self.send_command(7, 3, struct.pack('<BB', port, direction))
    def ble_cmd_hardware_io_port_config_function(self, port, function):
        self.send_command(7, 4, struct.pack('<BB', port, function))
    def ble_cmd_hardware_io_port_config_pull(self, port, tristate_mask, pull_up):
        self.send_command(7, 5, struct.pack('<BBB', port, tristate_mask, pull_up))
    def ble_cmd_hardware_io_port_write(self, port, mask, data):
        self.send_command(7, 6, struct.pack('<BBB', port, mask, data))
    def ble_cmd_hardware_io_port_read(self, port, mask):
        self.send_command(7, 7, struct.pack('<BB', port, mask))
    def ble_cmd_hardware_spi_config(self, channel, polarity, phase, bit_order, baud_e, baud_m):
        self.send_command(7, 8, struct.pack('<BBBBBB', channel, polarity, phase, bit_order, baud_e, baud_m))
    def ble_cmd_hardware_spi_transfer(self, channel, data):
        self.send_command(7, 9, struct.pack('<BB' + str(len(data)) + 's', channel, len(data), data))
    def ble_cmd_hardware_i2c_read(self, address, stop, length):
        self.send_command(7, 10, struct.pack('<BBB', address, stop, length))
    def ble_cmd_hardware_i2c_write(self, address, stop, data):
        self.send_command(7, 11, struct.pack('<BBB' + str(len(data)) + 's', address, stop, len(data), data))
    def ble_cmd_hardware_set_txpower(self, power):
        self.send_command(7, 12, struct.pack('<B', power))
    def ble_cmd_hardware_timer_comparator(self, timer, channel, mode, comparator_value):
        self.send_command(7, 13, struct.pack('<BBBH', timer, channel, mode, comparator_value))
    def ble_cmd_test_phy_tx(self, channel, length, type):
        self.send_command(8, 0, struct.pack('<BBB', channel, length, type))
    def ble_cmd_test_phy_rx(self, channel):
        self.send_command(8, 1, struct.pack('<B', channel))
    def ble_cmd_test_phy_end(self):
        self.send_command(8, 2)
    def ble_cmd_test_phy_reset(self):
        self.send_command(8, 3)
    def ble_cmd_test_get_channel_map(self):
        self.send_command(8, 4)
    def ble_cmd_test_debug(self, input):
        self.send_command(8, 5, struct.pack('<B' + str(len(input)) + 's', len(input), input))

    def parse_bgapi_packet(self, packet, callbacks=None):
        logger.debug('<=[ ' + hexlify_nice(packet) + ' ]')
        message_type, min_payload_length, packet_class, packet_command = struct.unpack('BBBB', packet[:4])
        rx_payload = packet[4:]
        if message_type == 0x20:
            # 0x20 = BGAPI command/response packet
            self.parse_bgapi_response(packet_class, packet_command, rx_payload, callbacks)
        elif message_type == 0xa0:
            # 0xa0 = BGAPI event packet
            self.parse_bgapi_event(packet_class, packet_command, rx_payload, callbacks)
        else:
            raise ValueError("Unsupported message type: 0x%02x" % message_type)


    def parse_bgapi_response(self, packet_class, packet_command, rx_payload, callbacks=None):
        if callbacks is None:
            callbacks = self._callbacks
        if False:
            pass
        elif packet_class == 0x01:  # Message class: System
            if packet_command == 0x03:
                result = rx_payload[:6]
                result = result[::-1]	# Reverse byte order for MAC address
                callbacks.ble_rsp_system_get_bt_address(result)
            else:
                logger.error('Unknown response message ID 0x%02x class System' % packet_command)
        elif packet_class == 0x0a:  # Message class: Generic Attribute Profile Server
            if packet_command == 0x02:
                result = struct.unpack('<H', rx_payload[:2])[0]
                logger.info('RSP-Gatt Server Write Attribute Value [%s]' % (RESULT_CODE[result]))
            else:
                logger.error('Unknown response message ID 0x%02x class Generic Attribute Profile Server' % packet_command)
        elif packet_class == 0x0d:  # Message class: Persistent Store
            if packet_command == 0x00:
                result = struct.unpack('<H', rx_payload[:2])[0]
                logger.info('RSP-Flash PS Dump [%s]' % (RESULT_CODE[result]))
            elif packet_command == 0x01:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_flash_ps_erase_all(result)
            elif packet_command == 0x03:
                result, key_len = struct.unpack('<HB', rx_payload[:3])
                key_value = struct.unpack('<' + str(key_len) + 's', rx_payload[3:3+key_len])[0]
                key_value_str = ':'.join([ '%02X' % ord(b) for b in key_value ])
                logger.info('RSP-Flash PS Load: Key Value:[%s] [%s]' % (key_value_str, RESULT_CODE[result]))
            else:
                logger.error('Unknown response message ID 0x%02x class Persistent Store' % packet_command)
        elif packet_class == 0x14:  # Message class: Mesh Node
            if packet_command == 0x00:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_mesh_node_init(result)
            elif packet_command == 0x01:
                result = struct.unpack('<H', rx_payload[:2])[0]
                logger.info('RSP-Start sending Unprovisioned Device Beacons [%s]' % (RESULT_CODE[result]))
            elif packet_command == 0x08:
                result = struct.unpack('<H', rx_payload[:2])[0]
                logger.info('RSP-Mesh Node Set Adv Event Filter [%s]' % (RESULT_CODE[result]))
            else:
                logger.error('Unknown response message ID 0x%02x class Mesh Node' % packet_command)
        elif packet_class == 0x1f:  # Message class: Bluetooth Mesh Generic Server Model
            if packet_command == 0x02:
                result = struct.unpack('<H', rx_payload[:2])[0]
                logger.info('RSP-Mesh Generic Server Publish [%s]' % (RESULT_CODE[result]))
            elif packet_command == 0x04:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_mesh_generic_server_init(result)
            else:
                logger.error('Unknown response message ID 0x%02x class Mesh Generic Server Model' % packet_command)
        elif packet_class == 0x1e:  # Message class: Bluetooth Mesh Generic Client Model
            if packet_command == 0x02:
                result = struct.unpack('<H', rx_payload[:2])[0]
                logger.info('RSP-Mesh Generic Client Publish [%s]' % (RESULT_CODE[result]))
            elif packet_command == 0x04:
                result = struct.unpack('<H', rx_payload[:2])[0]
                callbacks.ble_rsp_mesh_generic_client_init(result)
            else:
                logger.error('Unknown response message ID 0x%02x class Mesh Generic Client Model' % packet_command)
        else:
            logger.error('Unknown response message class 0x%02x' % packet_class)

    def parse_bgapi_event(self, packet_class, packet_command, rx_payload, callbacks=None):
        if callbacks is None:
            callbacks = self._callbacks
        if packet_class == 0x01:    # Message class: System
            if packet_command == 0x00:
                major, minor, patch, build, bootloader, hw, hash = struct.unpack('<HHHHIHI', rx_payload[:18])
                callbacks.ble_evt_system_boot(major=major, minor=minor, patch=patch, build=build, bootloader=bootloader, hw=hw, hash=hash)
            elif packet_command == 0x06:
                reason, len = struct.unpack('<HB', rx_payload[:3])
                value = rx_payload[3:3+len]
                callbacks.ble_evt_system_error(reason=reason, data=value)
            else:
                logger.error('Unknown event ID 0x%02x for event in class System' % packet_command)
        elif packet_class == 0x03:  # Message class: Generic Access Profile
            if packet_command == 0x00:
                pass    #Ignore evt_le_gap_scan_response
            elif packet_command == 0x01:
                pass    #Ignore evt_le_gap_adv_timeout
            else:
                logger.error('Unknown event ID 0x%02x for event in class Generic Access Profile' % packet_command)
        elif packet_class == 0x08:  # Message class: Connection Management
            if packet_command == 0x00:
                address, address_type, master, connection, bonding, advertiser = struct.unpack('<6sBBBBB', rx_payload[:11])
                callbacks.ble_evt_connection_opened(address=address, address_type=address_type, master=master, connection=connection, bonding=bonding, advertiser=advertiser)
            elif packet_command == 0x01:
                reason, connection = struct.unpack('<HB', rx_payload[:3])
                callbacks.ble_evt_connection_closed(reason=reason, connection=connection)
            elif packet_command == 0x02:
                logger.info('EVT-LE Connection Parameters (ignored)')
                pass    #Ignore evt_le_connection_parameters
            elif packet_command == 0x04:
                logger.info('EVT-LE Connection Phy Status (ignored)')
                pass    #Ignore evt_le_connection_phy_status
            else:
                logger.error('Unknown event ID 0x%02x for event in class Connection Management' % packet_command)
        elif packet_class == 0x0a:    # Message class: Generic Attribute Profile Server
            if packet_command == 0x02:  # evt_gatt_server_user_write_request
                connection, characteristic, att_opcode, offset, len = struct.unpack('<BHBHB', rx_payload[:7])
                value = rx_payload[6:6+len]
                callbacks.ble_evt_gatt_server_user_write_request(connection, characteristic, att_opcode, offset, value)
            else:
                logger.error('Unknown event ID 0x%02x for event in class Generic Attribute Profile Server' % packet_command)
        elif packet_class == 0x0d:    # Message class: Persistent Store
            if packet_command == 0x00:  # evt_gatt_server_user_write_request
                key, len = struct.unpack('<HB', rx_payload[:3])
                value = rx_payload[3:3+len]
                callbacks.ble_evt_flash_ps_key(key, value)
            else:
                logger.error('Unknown event ID 0x%02x for event in class Persistent Store' % packet_command)
        elif packet_class == 0x14:    # Message class: Mesh Node
            if packet_command == 0x00:
                provisioned, address, ivi = struct.unpack('<BHI', rx_payload[:7])
                callbacks.ble_evt_mesh_node_initialized(provisioned, address, ivi)
            elif packet_command == 0x01:
                iv_index, address = struct.unpack('<IH', rx_payload[:6])
                callbacks.ble_evt_mesh_node_provisioned(iv_index, address)
            elif packet_command == 0x06:
                result = struct.unpack('<H', rx_payload[:2])
                callbacks.ble_evt_mesh_node_provisioning_started(result)
            elif packet_command == 0x08:
                type, index, netkey_index = struct.unpack('<BHH', rx_payload[:5])
                callbacks.ble_evt_mesh_node_key_added(type, index, netkey_index)
            elif packet_command == 0x09:
                mesh_node_config_state, element_address, vendor_id, model_id = struct.unpack('<BHHH', rx_payload[:7])
                callbacks.ble_evt_mesh_node_model_config_changed(mesh_node_config_state, element_address, vendor_id, model_id)
            else:
                logger.error('Unknown event ID 0x%02x for event in class Mesh Node' % packet_command)
        elif packet_class == 0x1e:    # Message class: Bluetooth Mesh Generic Client Model
            if packet_command == 0x00:
                model_id, elem_index, client_address, server_address, remaining, flags, type, len = struct.unpack('<HHHHIHBB', rx_payload[:16])
                value = rx_payload[16:16+len]
                callbacks.ble_evt_mesh_generic_client_server_status(model_id, elem_index, client_address, server_address, remaining, flags, type, value)
            else:
                logger.error('Unknown event ID 0x%02x for event in class Bluetooth Mesh Generic Client Model' % packet_command)
        elif packet_class == 0x1f:    # Message class: Bluetooth Mesh Generic Server Model
            if packet_command == 0x00:
                model_id, elem_index, client_address, server_address, appkey_index, transition, delay, flags, type, len = struct.unpack('<HHHHHIHHBB', rx_payload[:20])
                value = rx_payload[20:20+len]
                callbacks.ble_evt_mesh_generic_server_client_request(model_id, elem_index, client_address, server_address, appkey_index, transition, delay, flags, type, value)
            else:
                logger.error('Unknown event ID 0x%02x for event in class Bluetooth Mesh Generic Server Model' % packet_command)
        else:
            logger.error('Unknown event class 0x%02x' % packet_class)

class BlueGigaCallbacks(object):
    def ble_rsp_system_reset(self):
        logger.info("RSP-System Reset")

    def ble_rsp_system_hello(self):
        logger.info("RSP-System Hello")

    def ble_rsp_system_address_get(self, address):
        logger.info("RSP-System Address Get - " + hexlify(address).decode('ascii').upper())

    def ble_rsp_system_get_bt_address(self, address):
        address = ':'.join([ '%02X' % ord(b) for b in address ])
        logger.info('RSP-Bt Address [%s]' % address)

    def ble_rsp_system_reg_write(self, result):
        logger.info("RSP-System Register Write: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_reg_read(self, address, value):
        logger.info("RSP-System Register Read - Address:%02X - Value:%02X" % (address, value))

    def ble_rsp_system_get_counters(self, txok, txretry, rxok, rxfail, mbuf):
        logger.info("RSP-System Get Counters %d %d %d %d %d" % (txok, txretry, rxok, rxfail, mbuf))

    def ble_rsp_system_get_connections(self, maxconn):
        logger.info("RSP-System Get Connections - Maximum Connections:%d" % (maxconn))

    def ble_rsp_system_read_memory(self, address, data):
        logger.info("RSP-System Read Memory: %08x %s" % (address, data))

    def ble_rsp_system_get_info(self, major, minor, patch, build, ll_version, protocol_version, hw):
        logger.info("RSP-System Get Info: %d.%d.%d.%d, ll:%d, proto:%d, hw:%d" %
                    (major, minor, patch, build, ll_version, protocol_version, hw))

    def ble_rsp_system_endpoint_tx(self, result):
        logger.info("RSP-System Endpoint TX: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_append(self, result):
        logger.info("RSP-System Whitelist Append: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_remove(self, result):
        logger.info("RSP-System Whitelist Remove: [%s]" % RESULT_CODE[result])

    def ble_rsp_system_whitelist_clear(self):
        logger.info("RSP-System Whitelist Clear")

    def ble_rsp_system_endpoint_rx(self, result, data):
        logger.info("RSP-System Endpoint RX: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_system_endpoint_set_watermarks(self, result):
        logger.info("RSP-System Endpoing Set Watermark: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_ps_defrag(self):
        logger.info("RSP-Flash PS Defrag")

    def ble_rsp_flash_ps_dump(self):
        logger.info("RSP-Flash PS Dump")

    def ble_rsp_flash_ps_erase_all(self, result):
        self._logger.info('RSP-Flash PS Erase All [%s]' % (RESULT_CODE[result]))

    def ble_rsp_flash_ps_save(self, result):
        logger.info("RSP-Flash PS Save: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_flash_ps_load(self, result, value):
        logger.info("RSP-Flash PS Load: [%s] - Value:%s" %  (RESULT_CODE[result], hexlify(value[::-1]).decode('ascii').upper()))

    def ble_rsp_flash_ps_erase(self):
        logger.info("RSP-Flash PS Erase")

    def ble_rsp_flash_erase_page(self, result):
        logger.info("RSP-Flash Erase Page: [%s]" %  RESULT_CODE[result])

    def ble_rsp_flash_write_words(self):
        logger.info("RSP-Flash Write Words")

    def ble_rsp_mesh_node_init(self, result):
        logger.info('RSP-Mesh Node Init [%s]' % (RESULT_CODE[result]))

    def ble_rsp_mesh_generic_server_init(self, result):
        logger.info('RSP-Mesh Generic Server Init [%s]' % (RESULT_CODE[result]))

    def ble_rsp_mesh_generic_client_init(self, result):
        logger.info('RSP-Mesh Generic Client Init [%s]' % (RESULT_CODE[result]))

    def ble_rsp_attributes_write(self, result):
        logger.info("RSP-Attributes Write: [%s]" %  RESULT_CODE[result])

    def ble_rsp_attributes_read(self, handle, offset, result, value):
        logger.info("RSP-Attributes Read [%s] - Handle:%d - Offset:%d - Value:%s" %  (RESULT_CODE[result], handle, offset, hexlify(value[::-1]).decode('ascii').upper()))

    def ble_rsp_attributes_read_type(self, handle, result, value):
        logger.info("RSP-Attributes Read Type [%s] - Handle:%d Value:%s" % (RESULT_CODE[result], handle, hexlify(value[::-1]).decode('ascii').upper()))

    def ble_rsp_attributes_user_read_response(self):
        logger.info("RSP-Attributes User Read Response")

    def ble_rsp_attributes_user_write_response(self):
        logger.info("RSP-Attributes User Write Response")

    def ble_rsp_attributes_send(self, result):
        logger.info("RSP-Attributes Send [%s]", RESULT_CODE[result])

    def ble_rsp_connection_disconnect(self, connection, result):
        logger.info("RSP-Connection Disconnect - Connection:%d - [%s]" % (connection, RESULT_CODE[result]))

    def ble_rsp_connection_get_rssi(self, connection, rssi):
        logger.info("RSP-Connection Get RSSI: (%d, %d)" % (connection, rssi))

    def ble_rsp_connection_update(self, connection, result):
        logger.info("RSP-Connection Update: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_version_update(self, connection, result):
        logger.info("RSP-Connection Version Update: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_channel_map_get(self, connection, map):
        logger.info("RSP-Connection Channel Map Get: (%d)" % (connection))

    def ble_rsp_connection_channel_map_set(self, connection, result):
        logger.info("RSP-Connection Channel Map Set: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_features_get(self, connection, result):
        logger.info("RSP-Connection Features Get: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_connection_get_status(self, connection):
        logger.info("RSP-Connection Get Status: (%d)" % (connection))

    def ble_rsp_connection_raw_tx(self, connection):
        logger.info("RSP-Connection Raw TX: (%d)" % (connection))

    def ble_rsp_attclient_find_by_type_value(self, connection, result):
        logger.info("RSP-Attribute Client Find By Type Value: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_by_group_type(self, connection, result):
        logger.info("RSP-Attribute Client Read By Group Type - Connection:%d - [%s]" % (connection, RESULT_CODE[result]))

    def ble_rsp_attclient_read_by_type(self, connection, result):
        logger.info("RSP-Attribute Client Read By Type: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_find_information(self, connection, result):
        logger.info("RSP-Attribute Client Find Information: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_by_handle(self, connection, result):
        logger.info("RSP-Attribute Client Read By Handle: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_attribute_write(self, connection, result):
        logger.info("RSP-Attribute Client Attribute Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_write_command(self, connection, result):
        logger.info("RSP-Attribute Client Write Command: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_indicate_confirm(self, result):
        logger.info("RSP-Attribute Client Indicate Confirm: [%s]" % RESULT_CODE[result])

    def ble_rsp_attclient_read_long(self, connection, result):
        logger.info("RSP-Attribute Client Read Long: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_prepare_write(self, connection, result):
        logger.info("RSP-Attribute Client Prepare Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_execute_write(self, connection, result):
        logger.info("RSP-Attribute Client Execute Write: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_attclient_read_multiple(self, connection, result):
        logger.info("RSP-Attribute Client Read Multiple: [%s] (%d)" % (RESULT_CODE[result], connection))

    def ble_rsp_sm_encrypt_start(self, handle, result):
        logger.info("RSP-SM Encryption Start: [%s] (%d)" % (RESULT_CODE[result], handle))

    def ble_rsp_sm_set_bondable_mode(self):
        logger.info("RSP-SM Bondable Mode")

    def ble_rsp_sm_delete_bonding(self, result):
        logger.info("RSP-SM Delete Bonding: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_sm_set_parameters(self):
        logger.info("RSP-SM Set Parameters")

    def ble_rsp_sm_passkey_entry(self, result):
        logger.info("RSP-SM Passkey Entry: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_sm_get_bonds(self, bonds):
        logger.info("RSP-SM Get Bonds")

    def ble_rsp_sm_set_oob_data(self):
        logger.info("RSP-SM Set OOB Data")

    def ble_rsp_gap_set_privacy_flags(self):
        logger.info("RSP-GAP Set Privacy Flags")

    def ble_rsp_gap_set_mode(self, result):
        logger.info("RSP-GAP Set Mode: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_discover(self, result):
        logger.info("RSP-GAP Discover: [%s]" % RESULT_CODE[result])

    def ble_rsp_gap_connect_direct(self, result, connection_handle):
        logger.info("RSP-GAP Connect Direct: [%s] (%d)" % (RESULT_CODE[result], connection_handle))

    def ble_rsp_gap_end_procedure(self, result):
        logger.info("RSP-GAP End Procedure: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_connect_selective(self, result, connection_handle):
        logger.info("RSP-GAP Connect Selective: [%s] (%d)" % (RESULT_CODE[result], connection_handle))

    def ble_rsp_gap_set_filtering(self, result):
        logger.info("RSP-GAP Set Filtering: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_scan_parameters(self, result):
        logger.info("RSP-GAP Set Scan Parameters: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_adv_parameters(self, result):
        logger.info("RSP-GAP Set Advertisement Parameters: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_adv_data(self, result):
        logger.info("RSP-GAP Set Advertisement Data: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_gap_set_directed_connectable_mode(self, result):
        logger.info("RSP-GAP Set Directed Connectable Mode: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_irq(self, result):
        logger.info("RSP-Hardware IO Port Config IRQ: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_set_soft_timer(self, result):
        logger.info("RSP-Hardware Set Soft Timer: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_adc_read(self, result):
        logger.info("RSP-Hardware ADC Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_direction(self, result):
        logger.info("RSP-Hardware IO Port Config Direction: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_function(self, result):
        logger.info("RSP-Hardware IO Port Config Function: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_config_pull(self, result):
        logger.info("RSP-Hardware IO Port Config Pullup: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_write(self, result):
        logger.info("RSP-Hardware IO Port Write: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_io_port_read(self, result, port, data):
        logger.info("RSP-Hardware IO Port Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_spi_config(self, result):
        logger.info("RSP-Hardware SPI Config: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_spi_transfer(self, result, channel, data):
        logger.info("RSP-Hardware SPI Transfer: [%s] (%d)" % (RESULT_CODE[result], channel))

    def ble_rsp_hardware_i2c_read(self, result, data):
        logger.info("RSP-Hardware I2C Read: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_hardware_i2c_write(self, written):
        logger.info("RSP-Hardware I2C Write: ")

    def ble_rsp_hardware_set_txpower(self):
        logger.info("RSP-Hardware Set TX Power")

    def ble_rsp_hardware_timer_comparator(self, result):
        logger.info("RSP-Hardware Timer Comparator: [%s]" % (RESULT_CODE[result]))

    def ble_rsp_test_phy_tx(self):
        logger.info("RSP-Test Phy TX")

    def ble_rsp_test_phy_rx(self):
        logger.info("RSP-Test Phy RX")

    def ble_rsp_test_phy_end(self, counter):
        logger.info("RSP-Test Phy End: %d" % (counter))

    def ble_rsp_test_phy_reset(self):
        logger.info("RSP-Test Phy Reset")

    def ble_rsp_test_get_channel_map(self, channel_map):
        logger.info("RSP-Test Get Channel Map")

    def ble_rsp_test_debug(self, output):
        logger.info("RSP-Test Debug")

    def ble_evt_system_boot(self, major, minor, patch, build, bootloader, hw, hash):
        logger.info("EVT-System Boot - Version:%d.%d.%d.%d - Bootloader Version:%d - hw:%d - Version hash:%s" %
                    (major, minor, patch, build, bootloader, hw, hex(hash)))
    
    def ble_evt_system_error(self, reason, data):
        logger.info("EVT-System Error - Reason:%s(%04X) - Data:%s" %
                    (RESULT_CODE[reason], reason, hexlify(data[::-1]).decode('ascii').upper()))
    
    def ble_evt_mesh_node_initialized(self, provisioned, address, ivi):
        logger.info("EVT-Mesh Node Initialized - Provisioned:%d - Primary Element Unicast Address:%d - IV index:%d" %
                    (provisioned, address, ivi))
    
    def ble_evt_mesh_node_provisioned(self, iv_index, address):
        logger.info("EVT-Mesh Node Provisioned - IV index:%d - My primary address:%04X" % (iv_index, address))
    
    def ble_evt_mesh_node_provisioning_started(self, result):
        logger.info("EVT-Mesh Node Provisioning Started - Result:%s" % (RESULT_CODE[result]))
    
    def ble_evt_mesh_node_key_added(self, type, index, netkey_index):
        if type == 0x00:
            key_type_str='Network'
            netkey_index_str = ''
        else:
            netkey_index_str = " - Netkey Index:%d" % (netkey_index)
            if type == 0x01:
                key_type_str='Application'
            else:
                logger.error('Unknown key type in event: %d', type)
                key_type_str='Unknown'
        logger.info("EVT-Mesh Node Key Added - Type:%s - Index:%d" % (key_type_str, index) + netkey_index_str)
    
    def ble_evt_mesh_node_model_config_changed(self, mesh_node_config_state, element_address, vendor_id, model_id):
        if mesh_node_config_state == 0x00:
            config_state_str='Model application key bindings'
        elif mesh_node_config_state == 0x01:
            config_state_str='Model publication parameters'
        elif mesh_node_config_state == 0x02:
            config_state_str='Model subscription list'
        else:
            config_state_str='Unknown'
            logger.error('Unknown Mesh Node Config State: %02X' % (mesh_node_config_state))
        logger.info("EVT-Mesh Node Model Config Changed - Config State:%s - Element Address:%04X - Vendor ID:%02X - Model ID:%02X" % (config_state_str, element_address, vendor_id, model_id))
    
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
        logger.info("EVT-Mesh Generic Server Client Request - Server Model ID:%04X - Element Index:%d" % (model_id, elem_index) +
                    " - Client Address:%04X - Server Address:%04X - Application Key Index:%d" % (client_address, server_address, appkey_index) +
                    transition_str +
                    delay_str +
                    flags_str +
                    " - Type:%02X - Value:%s" % (type, hexlify(value[::-1]).decode('ascii').upper()))
    
    def ble_evt_mesh_generic_client_server_status(self, model_id, elem_index, client_address, server_address, remaining, flags, type, value):
        flags_str=''
        if flags & 1:
            flags_str+='Nonrelayed'
        if flags_str != '':
            flags_str = ' - Flags:[' + flags_str + ']'
        logger.info("EVT-Mesh Generic Client Server Status - Server Model ID:%04X - Element Index:%d" % (model_id, elem_index) +
                    " - Client Address:%04X - Server Address:%04X - Remaining:%dms" % (client_address, server_address, remaining) +
                    flags_str +
                    " - Type:%02X - Value:%s" % (type, hexlify(value[::-1]).decode('ascii').upper()))

    def ble_evt_system_debug(self, data):
        logger.info("EVT-System Debug:", data)

    def ble_evt_system_endpoint_watermark_rx(self, endpoint, data):
        logger.info("EVT-System Endpoint Watermark RX: %d" % (endpoint))

    def ble_evt_system_endpoint_watermark_tx(self, endpoint, data):
        logger.info("EVT-System Endpoint Watermark TX: %d" % (endpoint))

    def ble_evt_system_script_failure(self, address, reason):
        logger.info("EVT-System Script Failure")

    def ble_evt_system_no_license_key(self):
        logger.info("EVT-System No License Key")

    def ble_evt_flash_ps_key(self, key, value):
        logger.info("EVT-Flash PS Key - Key:%04x - Value:%s" % (key, hexlify(value).decode('ascii').upper()))

    def ble_evt_attributes_value(self, connection, reason, handle, offset, value):
        logger.info("EVT-Attributes Value - Connection:%d - Reason:[%s] - Handle:%d - Offset:%d - " % (connection, ATTRIBUTE_CHANGE_REASON[reason], handle, offset) + \
            "Value:%s" % (hexlify(value).decode('ascii').upper(), ))

    def ble_evt_attributes_user_read_request(self, connection, handle, offset, maxsize):
        logger.info("EVT-Attributes User Read Request")

    def ble_evt_attributes_status(self, handle, flags):
        logger.info("EVT-Attributes Status - Handle:%d - Flags:[%s]" % (handle, ATTRIBUTE_STATUS_FLAGS[flags]))

    def ble_evt_connection_opened(self, address, address_type, master, connection, bonding, advertiser):
        result = address[::-1]
        result = ':'.join([ '%02X' % ord(b) for b in result ])
        logger.info("EVT-Connection Opened - Address:[%s] - " % (result, ) +
                    "Address Type:%d - Master:%d - Connection:%d - Bonding:%d - Advertiser:%d" % (address_type, master, connection, bonding, advertiser))

    def ble_evt_connection_closed(self, reason, connection):
        logger.info("EVT-Connection Closed - Reason:%s - Connection:%d " % (RESULT_CODE[reason], connection))

    def ble_evt_gatt_server_user_write_request(self, connection, characteristic, att_opcode, offset, value):
        logger.info("EVT-GATT Server User Write Request - Connection:%s - Characteristic:%04X - Opcode:%02x - Offset:%d - Value:%s" % (connection, characteristic, att_opcode, offset, hexlify(value).decode('ascii').upper()))

    def ble_evt_connection_status(self, connection, flags, address, address_type, conn_interval, timeout, latency, bonding):
        logger.info("EVT-Connection Status - Handle:%d - Flags:%02X - " % (connection, flags) +
                    "Address:%s - " % (hexlify(address[::-1]).decode('ascii').upper(), ) +
                    "Address Type:%d - Interval:%d - Timeout:%d - Latency:%d - Bonding:%d" % (address_type, conn_interval, timeout, latency, bonding))

    def ble_evt_connection_version_ind(self, connection, vers_nr, comp_id, sub_vers_nr):
        logger.info("EVT-Connection Version Ind")

    def ble_evt_connection_feature_ind(self, connection, features):
        logger.info("EVT-Connection Feature Ind")

    def ble_evt_connection_raw_rx(self, connection, data):
        logger.info("EVT-Connection Raw RX")

    def ble_evt_connection_disconnected(self, connection, reason):
        logger.info("EVT-Connection Disconnected - Connection:%d - Reason:%s" % (connection, RESULT_CODE[reason]))

    def ble_evt_attclient_indicated(self, connection, attrhandle):
        logger.info("EVT-Attribute Client Indicated - Connection:%d - Attribute Handle:%d" % (connection, attrhandle))

    def ble_evt_attclient_procedure_completed(self, connection, result, chrhandle):
        logger.info("EVT-Attribute Client Procedure Completed - Connection:%d - Result:[%s] - End Characteristic Handle:%d" %
                    (connection, RESULT_CODE[result], chrhandle))

    def ble_evt_attclient_group_found(self, connection, start, end, uuid):
        logger.info("EVT-Attribute Client Group Found - Connection:%d - Start Handle:%d - End Handle:%d - " % (connection, start, end) +
                    "UUID:" + hexlify(uuid[::-1]).decode('ascii').upper())

    def ble_evt_attclient_attribute_found(self, connection, chrdecl, value, properties, uuid):
        logger.info("EVT-Attribute Client Attribute Found")

    def ble_evt_attclient_find_information_found(self, connection, chrhandle, uuid):
        logger.info("EVT-Attribute Client Find Information Found - Connection:%d - Handle:%d - " % (connection, chrhandle) +
                    "UUID:" + hexlify(uuid[::-1]).decode('ascii').upper())

    def ble_evt_attclient_attribute_value(self, connection, atthandle, type, value):
        logger.info("EVT-Attribute Client Attribute Value - Connection:%d - Handle:%d - Type:%d - Value:%s" %
                    (connection, atthandle, type, hexlify(value).decode('ascii').upper()))

    def ble_evt_attclient_read_multiple_response(self, connection, handles):
        logger.info("EVT-Attribute Client Read Multiple Response")

    def ble_evt_sm_smp_data(self, handle, packet, data):
        logger.info("EVT-SM SMP Data")

    def ble_evt_sm_bonding_fail(self, handle, result):
        logger.info("EVT-SM Bonding Fail: [%s]" % (RESULT_CODE[result]))

    def ble_evt_sm_passkey_display(self, handle, passkey):
        logger.info("EVT-SM Passkey Display")

    def ble_evt_sm_passkey_request(self, handle):
        logger.info("EVT-SM Passkey Request")

    def ble_evt_sm_bond_status(self, bond, keysize, mitm, keys):
        logger.info("EVT-SM Bond Status - Bond:%d - Key Size:%d - MITM:%d - Keys Used Mask:%02X" %
                    (bond, keysize, mitm, keys))

    def ble_evt_gap_scan_response(self, rssi, packet_type, sender, address_type, bond, data):
        logger.info("EVT-GAP Scan Response - RSSI:%d - Packet Type:%d - " % (rssi, packet_type) +
                    "Sender:%02x:%02x:%02x:%02x:%02x:%02x - " % struct.unpack('BBBBBB', sender[::-1]) +
                    "Address Type:%d - Bond:%d - Data:" % (address_type, bond) +
                    hexlify(data).decode('ascii').upper())

    def ble_evt_gap_mode_changed(self, discover, connect):
        logger.info("EVT-GAP Mode Changed")

    def ble_evt_hardware_io_port_status(self, timestamp, port, irq, state):
        logger.info("EVT-Hardware IO Port Status")

    def ble_evt_hardware_soft_timer(self, handle):
        logger.info("EVT-Hardware Soft Timer")

    def ble_evt_hardware_adc_result(self, input, value):
        logger.info("EVT-Hardware ADC Result")
