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

class BleMeshNode(bgapi.api.BlueGigaCallbacks):
    def __init__(self, port, baud, timeout=0.1, bgapi_handler=None):
        #self._state=0
        #self._state_lock = threading.Lock()       # This mutex protects access to attribute state
        self._modem_init_done = threading.Event()
        self._flash_erase_done = threading.Event()
        self._get_bt_address_done = threading.Event()
        self._mesh_node_init_done = threading.Event()
        self._last_bt_address = None
        self._provisioning_occurred = threading.Event()
        self._mesh_generic_client_init_done = threading.Event()
        self._mesh_generic_server_init_done = threading.Event()
        if bgapi_handler is not None:
            self._bgapi=bgapi_handler
        else:
            self._bgapi=bgapi.api.BlueGigaAPI(port=port, callbacks=self, baud=baud, timeout=timeout)
        self._bgapi.start_daemon()
        self._logger = logging.getLogger("bgapi")
    
    def modem_reset(self, timeout=5):
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
        self._last_bt_address = None
        self._bgapi.ble_cmd_system_get_bt_address()
        if not self._get_bt_address_done.wait(timeout):
            self._logger.error('Get BT address timed out')
            raise Exception('Get BT address timed out')
        else:
            bt_address = self._last_bt_address
            self._last_bt_address = None
            return bt_address
    
    def mesh_generic_server_init(self, timeout=1):
        self._mesh_generic_server_init_done.clear()
        self._bgapi.ble_cmd_mesh_generic_server_init()
    
    def mesh_generic_client_init(self, timeout=1):
        self._mesh_generic_client_init_done.clear()
        self._bgapi.ble_cmd_mesh_generic_client_init()
    
    def mesh_node_init(self, timeout=1, init_server=True, init_client=True):
        self._mesh_node_init_done.clear()
        self._bgapi.ble_cmd_mesh_node_init()
        if not self._mesh_node_init_done.wait(timeout):
            self._logger.error('Mesh node init timed out')
            raise Exception('Mesh node init timed out')
        self._mesh_generic_server_init_done.clear()
        self.mesh_generic_server_init()
        if not self._mesh_generic_server_init_done.wait(timeout):
            self._logger.error('Mesh generic server init timed out')
            raise Exception('Mesh generic server init timed out')
        self._mesh_generic_client_init_done.clear()
        self.mesh_generic_client_init()
        if not self._mesh_generic_client_init_done.wait(timeout):
            self._logger.error('Mesh generic client init timed out')
            raise Exception('Mesh generic client init timed out')
    
    def start_advertising_unprovisioned(self):
        self._provisioning_occurred.clear()
        self._bgapi.ble_cmd_mesh_node_start_unprov_beaconing(1 | 2)
    
    def wait_provisioned(self, timeout=None):
        if not self._provisioning_occurred.wait(timeout):
            self._logger.error('Wait for provisioned timed out')
    
    def ble_evt_system_boot(self, major, minor, patch, build, bootloader, hw, hash):
        self._logger.info("EVT-System Boot - Version:%d.%d.%d.%d - Bootloader Version:%d - hw:%d - Version hash:%s" %
                    (major, minor, patch, build, bootloader, hw, hex(hash)))
        self._modem_init_done.set()
    
    def ble_rsp_system_get_bt_address(self, address):
        address = ':'.join([ '%02X' % ord(b) for b in address ])
        self._logger.info('RSP-Bt Address [%s]' % address)
        self._last_bt_address = address # Record the address we just got, it will be used by blocking method get_bt_address()
        self._get_bt_address_done.set()

    def ble_rsp_flash_ps_erase_all(self, result):
        self._logger.info('RSP-Flash PS Erase All [%s]' % (RESULT_CODE[result]))
        if (result==0):
            self._flash_erase_done.set()
        else:
            self._logger.error('Flash erase command failed')

    def ble_rsp_mesh_node_init(self, result):
        self._logger.info('RSP-Mesh Node Init [%s]' % (RESULT_CODE[result]))
        if (result==0):
            self._mesh_node_init_done.set()
        else:
            self._logger.error('Mesh node init command failed')

    def ble_rsp_mesh_generic_server_init(self, result):
        self._logger.info('RSP-Mesh Generic Server Init [%s]' % (RESULT_CODE[result]))
        if (result==0):
            self._mesh_generic_server_init_done.set()
        else:
            self._logger.error('Mesh generic server init command failed')

    def ble_rsp_mesh_generic_client_init(self, result):
        self._logger.info('RSP-Mesh Generic Client Init [%s]' % (RESULT_CODE[result]))
        if (result==0):
            self._mesh_generic_client_init_done.set()
        else:
            self._logger.error('Mesh generic client init command failed')

    def ble_evt_mesh_node_provisioned(self, iv_index, address):
        self._logger.info("EVT-Mesh Node Provisioned - IV index:%d - My primary address:%04x" % (iv_index, address))
        self._provisioning_occurred.set()


def example_ble_mesh_node():
    term = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(PORT + ': %(asctime)s - %(name)s - %(levelname)s - %(message)s')
    term.setFormatter(formatter)
    api_logger = logging.getLogger("bgapi")
    api_logger.addHandler(term)
    api_logger.setLevel(level=logging.DEBUG)
    
    logger=api_logger
    
    decommission_node = False   # Set this to True if you want to force the node out of its (possibly) currently commissionned BLE mesh network
    
    btmesh=BleMeshNode(port=PORT, baud=57600)
    if decommission_node:
        btmesh.flash_erase()
    
    btmesh.modem_reset()
    logger.info('Our Bluetooth address is:' + str(btmesh.get_bt_address()))
    
    btmesh._bgapi.ble_cmd_gatt_server_write_attribute_value(11, 0, 'fake node') # see app.c#L110 gattdb_device_name==11
    time.sleep(0.5)
    btmesh._bgapi.ble_cmd_mesh_node_set_adv_event_filter(0,'') # see main.c#L284    (was 0x07)
    time.sleep(0.5)
    btmesh.mesh_node_init()
    
    if decommission_node:
        btmesh.start_advertising_unprovisioned()
        logger.info('Waiting to be provisioned...')
        btmesh.wait_provisioned()
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
        btmesh._bgapi.ble_cmd_mesh_generic_client_publish(0x1000, 0, i, 0, 0, 0, 0, struct.pack('<B', i%2))
        time.sleep(15)

    # Will get evt_mesh_node_provisioning_started event
    # Allows to blink LEDs to show start of provisionning
    # Will then get either gecko_evt_mesh_node_provisioned_id or gecko_evt_mesh_node_provisioning_failed_id event
    btmesh._bgapi.t.join()

    
    logger.info('Execution finished')

if __name__ == "__main__":
    example_ble_mesh_node()
    time.sleep(0.5)  # Give it a moment for the responses to come back and get logged

