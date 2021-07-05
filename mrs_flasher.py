#!python3
#
# Flash programmer for various MRS devices.
#
# Should work with any CAN adapter supported by python-can, but
# optimised for use with a homebrew adapter that supports power
# control.
#
# (The MRS adapter has the ability to switch T30 and T15, but
#  their software doesn't appear to actually exploit it as a way
#  of recovering bricked units...)
#
# Newer S-record input includes S0 records denoting the intended
# target device part / order numbers and hardware revisions, e.g.:
#
# MRS-Check>>>400803,400948,401395,401380,400817,400811,400814,400819,401368<<<B,B1 // V2.6.0.0 Lib-S32K-2.6.0
# MRS-ProgData>>>125 kBit;V0.0.0;CC16WP Application
# MRS-ExtraData>>>1.154.300.00,1.154.211.00,1.154.300.0010,1.154.300.0200,1.154.300.10,1.154.302.00,1.154.302.03,1.154.310.00,1.154.320.00,1.154.330.00,1.154.343.03,1.154.;B,B1;
#
# An S5 record may also be present.
#

import argparse
import struct
import time
from pathlib import Path
from binascii import crc32
import can

# MRS-used CAN IDs
ACK_ID = 0x1ffffff0
CMD_ID = 0x1ffffff1
RSP_ID = 0x1ffffff2
SREC_ID = 0x1ffffff3
DATA_ID = 0x1ffffff4

# Programmer-specific messages
CONSOLE_ID = 0x1ffffffe
MJS_POWER_ID = 0x0fffffff


EEPROM_STARTKENNER = 1331
EEPROM_MAP = [
    # (format, name)
    # ('2B' '??'),
    # ('>H' 'Startkenner'),
    ('>I',  'Serial_Number'),
    ('12s', 'Part_Number'),
    ('12s', 'Drawing_Number'),
    ('20s', 'Name'),
    ('8s',  'Order_Number'),
    ('8s',  'Test_Date'),
    ('>H',  'HW_Version'),
    ('B',   'Reset_Counter'),
    ('>H',  'Library_Version'),
    ('B',   'ResetReasonCounter_LVD'),
    ('B',   'ResetReasonCounter_LOC'),
    ('B',   'ResetReasonCounter_ILAD'),
    ('B',   'ResetReasonCounter_ILOP'),
    ('B',   'ResetReasonCounter_COP'),
    ('B',   'MCU_Type'),
    ('B',   'HW_CAN_Active'),
    ('3B',  'Bootloader_Werksdaten_Reserve1'),
    ('>H',  'Bootloader_Version'),
    ('>H',  'Prog_State'),
    ('>H',  'Portbyte1'),
    ('>H',  'Portbyte2'),
    ('>H',  'Baudrate_Bootloader1'),
    ('>H',  'Baudrate_Bootloader2'),
    ('B',   'Bootloader_ID_Ext1'),
    ('>I',  'Bootloader_ID1'),
    ('B',   'Bootloader_ID_CRC1'),
    ('B',   'Bootloader_ID_Ext2'),
    ('>I',  'Bootloader_ID2'),
    ('B',   'Bootloader_ID_CRC2'),
    ('20s', 'Sofware_Version'),
    ('30s', 'Module_Name'),
    ('B',   'BL_CAN_Bus'),
    ('>H',  'COP_WD_Timeout'),
    ('7B',  'Bootloader_Configdaten_Reserve1')
]


class MessageError(Exception):
    """a received message was not as expected"""
    pass


class ModuleError(Exception):
    """the module did something unexpected"""
    pass


class TXMessage(can.Message):
    """
    Abstract for messages that will be sent.

    Concrete classes set self._format and pass args to struct.pack()
    that format to __init__.
    """
    def __init__(self, arbitration_id, *args):
        super().__init__(arbitration_id=arbitration_id,
                         is_extended_id=True,
                         dlc=struct.calcsize(self._format),
                         data=struct.pack(self._format, *args))


class MSG_mjs_power(TXMessage):
    """mjs adapter power control message"""
    _format = 'B'

    def __init__(self, t30_state, t15_state):
        if not t30_state:
            arg = 0x00
        elif not t15_state:
            arg = 0x01
        else:
            arg = 0x03
        super().__init__(MJS_POWER_ID, arg)


class MSG_ping(TXMessage):
    """all-call message, solicits 'ack' from every module"""
    _format = '>H'

    def __init__(self):
        super().__init__(CMD_ID, 0)


class MSG_select(TXMessage):
    """selects a specific module for subsequent non-addressed commands"""
    _format = '>HI'

    def __init__(self, module_id):
        super().__init__(CMD_ID,
                         0x2010,
                         module_id)


class MSG_read_eeprom(TXMessage):
    """requests data from (probably) the EEPROM"""
    _format = '>HHB'

    def __init__(self, address, count):
        super().__init__(CMD_ID,
                         0x2003,
                         address,
                         count)


class MSG_program(TXMessage):
    """commands the selected device to enter programming mode"""
    _format = '>H'

    def __init__(self):
        super().__init__(CMD_ID, 0x2000)


class MSG_erase(TXMessage):
    """commands the selected device to erase the flash"""
    _format = '>H'

    def __init__(self):
        super().__init__(CMD_ID, 0x0202)


class MSG_srecord(can.Message):
    """raw S-record data"""
    def __init__(self, data):
        super().__init__(arbitration_id=SREC_ID,
                         is_extended_id=True,
                         dlc=len(data),
                         data=data)


class RXMessage(object):
    """
    Abstract for messages that have been received.

    Concretes set self._format to struct.unpack() received bytes,
    and self._filter to a list of tuple-per-unpacked-item with each
    tuple containing True/False and, if True, the required value.
    """
    def __init__(self, expected_id, raw):
        if raw.arbitration_id != expected_id:
            raise MessageError(f'expected reply with ID 0x{expected_id:x} '
                               f'but got {raw}')
        if raw.dlc != struct.calcsize(self._format):
            raise MessageError(f'expected reply with length {expected_dlc} '
                               f'but got {raw}')

        self._data = raw.data
        self._values = struct.unpack(self._format, self._data)
        for (index, (check, value)) in enumerate(self._filter):
            if check and value != self._values[index]:
                raise MessageError(f'reply field {index} is '
                                   f'0x{self._values[index]:x} '
                                   f'but expected 0x{value:x}')

    @classmethod
    def len(self):
        return struct.calcsize(self._format)


class MSG_ack(RXMessage):
    """broadcast message sent by module on power-up, reboot or crash"""
    _format = '>BIBH'
    _filter = [(False, 0),
               (False, 0),
               (False, 0),
               (False, 0)]
    REASON_MAP = {
        0x00: 'power-on',
        0x01: 'reset',
        0x11: 'low-voltage reset',
        0x21: 'clock lost',
        0x31: 'address error',
        0x41: 'illegal opcode',
        0x51: 'watchdog timeout'
    }
    STATUS_MAP = {
        0: 'OK',
        4: 'NO PROG'
    }

    def __init__(self, raw):
        super().__init__(expected_id=ACK_ID,
                         raw=raw)
        (self.reason_code,
         self.module_id,
         self.status_code,
         self.sw_version) = self._values
        try:
            self.reason = self.REASON_MAP[self.reason_code]
        except KeyError:
            self.reason = 'unknown'
        try:
            self.status = self.STATUS_MAP[self.status_code]
        except KeyError:
            self.status = "unknown"


class MSG_selected(RXMessage):
    """
    Response to MSG_select confirming selection.

    self.sw_version appears to be 0 if the app is running,
    or !0 if in program mode
    """
    _format = '>HIH'
    _filter = [(True, 0x2110),
               (False, 0),
               (False, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, self.module_id, self.sw_version) = self._values


class MSG_program_nak(RXMessage):
    """
    Response sent to MSG_program when the app is running.
    Module reboots after sending this message (and sends MSG_ack
    with reason='reboot'), apparently into the bootloader.
    """
    _format = '>HIH'
    _filter = [(True, 0x2fff),
               (False, 0),
               (False, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, self.module_id, _) = self._values


class MSG_program_ack(RXMessage):
    """response sent to MSG_program when running the bootloader"""
    _format = '>HIH'
    _filter = [(True, 0x2100),
               (False, 0),
               (False, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, self.module_id, _) = self._values


class MSG_progress(RXMessage):
    """
    Sent in a stream after MSG_erase; self.progress counts from
    zero to self.limit.
    """
    _format = '>BBBB'
    _filter = [(True, 0),
               (False, 0),
               (False, 0),
               (True, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, self.progress, self.limit, _) = self._values


class MSG_erase_done(RXMessage):
    """sent after erase is completed"""
    _format = '>BBBB'
    _filter = [(True, 0),
               (True, 0),
               (False, 0),
               (True, 1)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        if self._values[2] not in [0, 0xff]:
            raise MessageError(f'unexpected data[2] {self._values[2]:#02x}')


class MSG_srec_start_ok(RXMessage):
    """sent in response to the first part of an S-record"""
    _format = '>BBBBB'
    _filter = [(True, 0),
               (True, 1),
               (True, 1),
               (True, 1),
               (True, 1)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)


class MSG_srec_cont_ok(RXMessage):
    """sent in response to an internal part of an S-record"""
    _format = '>BB'
    _filter = [(True, 0),
               (True, 1)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)


class MSG_srec_end_ok(RXMessage):
    """sent in response to an internal part of an S-record"""
    _format = '>BBB'
    _filter = [(True, 0),
               (True, 0),
               (True, 1)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)


class MSG_srecords_done(RXMessage):
    """sent in response to an S9 record at the end of the file"""
    _format = '>BBB'
    _filter = [(True, 0),
               (True, 0x12),
               (True, 0x34)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)


class MSG_no_program(RXMessage):
    """
    Sent after MSG_srecords_done if the ROM doesn't like the program,
    e.g. it doesn't have a reset vector.
    """
    _format = '>BBBBB'
    _filter = [(True, 0),
               (True, 2),
               (True, 2),
               (True, 2),
               (True, 2)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)


class CANInterface(object):
    def __init__(self, args):
        self._bus = can.interface.Bus(bustype=args.interface_type,
                                      channel=args.interface,
                                      bitrate=args.can_speed,
                                      sleep_after_open=0.2)
        self._verbose = args.verbose
        self._have_power_control = args.interface_power_control

        # filter just the IDs we expect to see coming from the module
        # self._bus.set_filters([
        #     {"can_id": 0x1ffffff0,  "can_mask": 0x1ffffff0, "extended": True}
        # ])

    def send(self, message):
        """send the message"""
        log(f'CAN TX: {message}')
        self._bus.send(message, 1)

    def recv(self, timeout=2):
        """
        wait for a message

        Note the can module will barf if a bad message is received, so we need
        to catch this and retry
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            wait_time = deadline - time.time()
            try:
                msg = self._bus.recv(wait_time)
                if msg is not None:
                    log(f'CAN RX: {msg}')
                return msg
            except Exception:
                pass
        return None

    def set_power_off(self):
        if self._have_power_control:
            self.send(MSG_mjs_power(False, False))

    def set_power_t30(self):
        if self._have_power_control:
            self.send(MSG_mjs_power(True, False))
        else:
            print('NOTE: turn on power now...')

    def set_power_t30_t15(self):
        if self._have_power_control:
            self.send(MSG_mjs_power(True, True))
        else:
            print('NOTE: turn on power now...')

    def detect(self):
        """
        Power on the module and listen for it to sign on.
        Send it a ping to keep it in the bootloader for a while.
        Returns the ID of the detected module.
        """
        self.set_power_off()
        while self.recv(0.25) is not None:
            # drain buffered messages
            pass
        self.set_power_t30()
        while True:
            rsp = self.recv(2)
            if rsp is None:
                raise ModuleError('no power-on message from module')
            try:
                signon = MSG_ack(rsp)
                break
            except MessageError as e:
                raise ModuleError(f'unexpected power-on message '
                                  f'from module: {rsp}')
        self.send(MSG_ping())
        rsp = self.recv()
        if rsp is None:
            raise ModuleError('no ping response from module')
        try:
            signon = MSG_ack(rsp)
        except MessageError as e:
            raise ModuleError(f'unexpected ping response from '
                              'module : {rsp}')
        return signon.module_id

    def scan(self):
        """
        Send the all-call message and collect replies.

        We spam the message for a while at a short interval
        and collect / de-duplicate replies. If a module is in
        a crashloop it may not respond to the first ping, but
        in theory we'll catch it in the bootloader eventually.
        """
        print('Scanning...')
        modules = dict()
        scan_end_time = time.time() + 1.0
        self.send(MSG_ping())
        while True:
            rsp = self.recv(0.05)
            if rsp is not None:
                try:
                    ack = MSG_ack(rsp)
                except MessageError as e:
                    raise MessageError('unexpected programming traffic '
                                       'on CAN bus during scan')
                modules[ack.module_id] = {
                    'status': ack.status,
                    'reason': ack.reason,
                    'sw_ver': ack.sw_version
                }
            elif time.time() < scan_end_time:
                self.send(MSG_ping())
            else:
                break
        return modules


class S32_Srecords_(object):
    '''Load and fix up S-records for S32-based targets'''

    class Srecord(object):
        def __init__(self, flavor, address, data):
            self._flavor = flavor
            self._address = address
            self._data = data

        @classmethod
        def from_line(cls, line):
            if ((line[0] != 'S') or (line[1] not in '135790')):
                raise RuntimeError(f'malformed or unsupported S-record header {line}')
            count = int(f'0x{line[2:4]}', 16)
            if len(line) != (count + 4):
                raise RuntimeError(f'malformed S-record length {line}')
            payload = bytes.fromHex(line[2:-2])

            flavor = line[1]
            check = int(f'0x{line[-2:]}', 16)

            # parse selected S-records
            if flavor == '0':
                address = None
                data = payload[2:].decode('ascii')
            elif flavor == '1':
                (address) = struct.unpack_from('<H', payload)
                data = payload[2:]
            elif flavor == '3':
                (address) = struct.unpack_from('<I', payload)
                data = payload[4:]
            elif flavor == '5':
                address = struct.unpack_from('<H', payload)
                data = None
            elif flavor == '7':
                (address) = struct.unpack_from('<I', payload)
                data = None
            elif flavor == '9':
                (address) = struct.unpack_from('<H', payload)
                data = None

            return Srecord(flavor, address, data)

        @property
        def flavor(self):
            return self._flavor

        @property
        def address(self):
            return self._address

        @property
        def data(self):
            return self._data

    def __init__(self, path, args, mcu_type):

        # configure properties for the MCU
        if mcu_type == 6:
            # S32K144
            self._flash_base = 0x10000
            flash_limit = 0x80000
        else:
            raise RuntimeError(f'unsupported MCU type {mcu_type}')

        # read the input file
        try:
            with path.open() as f:
                lines = f.readlines()
        except Exception as e:
            raise RuntimeError(f'could not read S-records from {path}')

        # convert lines to S-records
        mem_records = dict()
        self._image_entry = None
        header_base = flash_limit
        image_limit = self._flash_base
        for line in lines:
            srec = Srecord.from_line(line)

            # flash data
            if srec.flavor == '3':
                limit = srec.address + len(srec.data)
                if (srec.address < self._flash_base) or (limit > flash_limit):
                    raise RuntimeError(f'data outside flashable area')
                mem_records[srec.address] = srec.data
                if limit > image_limit:
                    image_limit = limit
                if srec.address < app_base:
                    app_base = srec.address

            # entrypoint
            if srec.flavor == '7':
                self._image_entry = srec.address

        # sanity-check the entrypoint
        if self._image_entry is None:
            raise RuntimeError(f'missing entrypoint')
        if (self._image_entry < app_base) or (self._image_entry > image_limit):
            raise RuntimeError(f'entrypoint outside app')

        # image must start at base of flash
        if header_base != self._flash_base:
            raise RuntimeError(f'data does not start at base of flash')

        # round the image limit up to a multiple of 256 (only for S32)
        mod = image_limit % 256
        if mod != 0:
            image_limit += 256 - mod

        # build the memory array, pad with zeros
        self._mem_buf = bytearray(image_limit - self._flash_base)

        # and fill it with srecord data
        for srec in mem_records:
            rec_offset = srec.address - self._flash_base
            rec_limit = rec_offset + len(srec.data)
            self._mem_buf[rec_offset:rec_limit] = srec.data

        # do header fixups
        self._fix_flash_header()

    def _fix_flash_header(self):
        # typedef struct
        # {
        #     uint32_t header_key;          default 0x12345678
        #     uint32_t header_crc;          crc32 from 0x10008-0x10fff
        #     uint32_t app_header_version;  default 1
        #     uint32_t application_crc;     crc32 from 0x11000 of application_length
        #     uint32_t application_length;  app length (multiple of 256)
        #     uint8_t sw_version[32];       default "NO PROG"
        #     uint8_t reserve[460];         zeros
        #     uint8_t signature_key[512];   zeros
        # } struct_hal_sys_app_header_t;
        header_fmt = '<IIIII20s'

        # parse the current header state
        (header_key,
         header_crc,
         app_header_version,
         application_crc,
         application_length,
         sw_version) = struct.unpack_from(header_fmt, mem_buf, 0)

        if app_header_version != 1:
            raise RuntimeError(f'unsupported flash header version {app_header_version}')

        #  check whether the header has already been populated...
        if application_crc == 0:
            # compute the application CRC and length
            application_crc = crc32(self._mem_buf[0x1000:])
            application_length = len(self._mem_buf) - 0x1000

            # Fill in the header
            #
            struct.pack_into(self._mem_buf, header_fmt, 0,
                             0x12345678,            # header_key
                             0,                     # header_crc
                             1,                     # app_header_version
                             application_crc,       # application_crc
                             application_length,    # application_length
                             'NO_PROG\0\0\0\0\0\0\0\0\0\0\0\0\0')

            # compute the header CRC
            header_crc = crc32(self._mem_buf[0x8:0x1000])

            # rewrite the header with corrected CRC
            struct.pack_into(self._mem_buf, header_fmt, 0,
                             0x12345678,            # header_key
                             header_crc,            # header_crc
                             1,                     # app_header_version
                             application_crc,       # application_crc
                             application_length,    # application_length
                             'NO_PROG\0\0\0\0\0\0\0\0\0\0\0\0\0')

    @property
    def text_records(self):
        """generator yielding text S-records"""

        for offset in range(0, len(self._mem_buf), 32):
            address = self._flash_base + offset
            data = self._mem_buf[offset:offset + 32]
            yield(f'S325{address:08x}{data.hex()}{self.sum(data):02x}')

        data = struct.pack('<I', self._image_entry)
        yield(f'S705{data.hex()}{self.sum(data):02x}')

    @property
    def upload_records(self):
        """generator yielding S-records in ready-to-send format"""
        for srec in self.text_records:
            # first two bytes to send are ascii, remainder are literals
            yield bytearray(srec[0:2], 'ascii') + bytes.fromhex(srec[2:])

    @staticmethod
    def sum(data):
        check = 0
        for b in data:
            check += b
        return check & 0xff


class HS08_Srecords(object):
    '''read S-records and fix up for HCS08-based targets'''

    @staticmethod
    def sum(srec):
        count = int(f'0x{srec[2:4]}', 16)
        sum = 0
        for ofs in range(2, 2 + (count * 2), 2):
            sum += int(f'0x{srec[ofs:ofs+2]}', 16)
        return (~sum) & 0xff

    def __init__(self, path, args):
        self._hexbytes = dict()

        # read the input file
        try:
            with path.open() as f:
                lines = f.readlines()
        except Exception as e:
            raise RuntimeError(f'could not read S-records from {path}')

        # populate the bytes array with data from S1 records
        for line in lines:
            if line[0] != 'S':
                raise RuntimeError(f'malformed S-record: {line}')
            if line[1] in '2378':
                raise RuntimeError(f'unsupported S{line[1]} record: {line}')
            if line[1] != '1':
                # ignore anything that's not an S1 record; we discard S[056],
                # and fake S9 at the end
                continue

            # get the starting address of the line
            address = int(f'0x{line[4:8]}', 16)

            # and paste bytes into memory
            hexbytes = line[8:-3]
            # log(f"{address:04x}: {hexbytes}")
            self._insert_bytes(address, hexbytes)

        # locate the reset vector
        self._entry = self._vector(0)
        if self._entry is None:
            raise RuntimeError("no reset vector")

        # extract vectors and patch them into the thunk space
        try:
            default_vector = self._vector(32)
        except KeyError:
            default_vector = self._entry

        for number in range(0, 32):
            self._insert_thunk(number, default_vector)

        # prune values outside the writable ROM space
        for address in sorted(self._hexbytes):
            if ((address < 0x2200) or (address > 0xbdff)):
                # log(f"remove {address:04x}")
                del self._hexbytes[address]

    def _insert_bytes(self, address, hexbytes):
        while len(hexbytes) > 0:
            self._hexbytes[address] = hexbytes[0:2]
            hexbytes = hexbytes[2:]
            address += 1

    def _insert_thunk(self, number, default_vector):
        try:
            vector = self._vector(number)
        except KeyError:
            vector = default_vector
        self._insert_bytes(0xaffc - (number * 4), "CC" + vector + "9D")

    def _vector(self, number):
        address = 0xfffe - (number * 2)
        return self._word(address)

    def _word(self, address):
        try:
            hi = self._hexbytes[address]
            lo = self._hexbytes[address + 1]
            return hi + lo
        except KeyError:
            return None

    @property
    def text_records(self):
        """generator yielding text S-records"""
        addresses = sorted(self._hexbytes)

        while len(addresses):

            # address of next S1 record to emit
            srec_addr = addresses[0]
            srec_hexbytes = ""
            byte_addr = srec_addr

            while (byte_addr in addresses) and len(srec_hexbytes) < 64:
                srec_hexbytes += self._hexbytes[byte_addr]
                addresses = addresses[1:]
                byte_addr += 1

            srec = f"S1{(len(srec_hexbytes) >> 1) + 3:02X}{srec_addr:04X}{srec_hexbytes}"
            srec += f"{self.sum(srec):02X}"
            yield srec

        yield "S9030000FC"

    @property
    def upload_records(self):
        """generator yielding S-records in ready-to-send format"""
        for srec in self.text_records:
            # first two bytes to send are ascii, remainder are literals
            yield bytearray(srec[0:2], 'ascii') + bytes.fromhex(srec[2:])


class Module(object):
    def __init__(self, interface, module_id, args):
        self._interface = interface
        self._module_id = module_id
        self._verbose = args.verbose

    def _cmd(self, message):
        """send a message, wait for a response"""
        self._interface.send(message)
        rsp = self._interface.recv()
        if rsp is None:
            raise ModuleError(f'timed out waiting for a reply to {message} ')
        return rsp

    def _select(self):
        """select the module for further commands"""
        rsp = self._cmd(MSG_select(self._module_id))
        sel = MSG_selected(rsp)
        if (sel.module_id != self._module_id):
            raise CanError('wrong module responded to selection')
        return sel.sw_version

    def _read_eeprom(self, address, length):
        """read bytes from the EEPROM"""
        result = bytearray()
        while length > 0:
            amount = length if length <= 8 else 8
            rsp = self._cmd(MSG_read_eeprom(address, amount))
            length -= amount
            address += amount
            result += rsp.data
        return result

    def _wait_for_boot(self, timeout):
        """wait for the message broadcast by a module rebooting"""
        while True:
            rsp = self._interface.recv(timeout)
            if rsp is None:
                raise ModuleError('did not see module reboot message')
            try:
                boot_message = MSG_ack(rsp)
                if boot_message.module_id != self._module_id:
                    continue
                if boot_message.reason != 'reboot':
                    continue
                break
            except MessageError:
                pass

    def _enter_flash_mode(self):
        """put the module into flash/erase mode"""
        self._select()
        rsp = self._cmd(MSG_program())
        try:
            will_reboot = MSG_program_nak(rsp)
            self._wait_for_boot(2)
            self._select()
            rsp = self._cmd(MSG_program())
        except MessageError:
            pass
        ready = MSG_program_ack(rsp)

    def _print_progress(self, title, limit, position):
        scale = 60 / limit
        hashes = int(position * scale)
        bar = '#' * hashes + '.' * (60 - hashes)
        print(f'\r{title:<8} [{bar}] {position}/{limit}', end='')
        if position == limit:
            print('')

    def _erase_progress(self, title):
        """monitor erase progress"""
        while True:
            rsp = self._interface.recv(2)
            if rsp is None:
                raise ModuleError('did not see expected module '
                                  'progress message')
            try:
                done = MSG_erase_done(rsp)
                print('')
                break
            except MessageError as e:
                pass
            try:
                progress = MSG_progress(rsp)
            except MessageError as e:
                raise ModuleError(f'got unexpected message {rsp} '
                                  f'instead of erase progress / completion')
            self._print_progress(title, progress.limit, progress.progress)

    def _erase(self):
        """erase the currently-selected module"""
        self._interface.send(MSG_erase())
        self._erase_progress("ERASE ")

    def _program(self, srecords):
        """flash srecords to the currently-selected module"""
        progress = 1
        records = list(srecords.upload_records)
        for srec in records:
            for index in range(0, len(srec), 8):
                rsp = self._cmd(MSG_srecord(srec[index:index+8]))
            if rsp is None:
                raise ModuleError(f'timed out waiting for response')

            self._print_progress("FLASH", len(records), progress)
            progress += 1

            if rsp.data[0] != 0:
                raise ModuleError(f'module rejected S-record')
            try:
                ack = MSG_srecords_done(rsp)
                log(f'DONE: {rsp}')
                print('')
                return
            except MessageError:
                continue
        raise ModuleError(f'expected S-record end OK message, but not received'
                          f' - check S-records for S9 at end')

    def upload(self, srecords):
        """flash the module with the supplied program"""
        self._enter_flash_mode()
        self._erase()
        self._program(srecords)

    @property
    def raw_properties(self):
        """get raw EEPROM properties"""
        self._select()
        return self._read_eeprom(0, 0x800)

    @property
    def properties(self):
        """decode EEPROM contents"""
        self._select()
        header = self._read_eeprom(2, 2)
        (magic,) = struct.unpack(">H", header)
        if magic != EEPROM_STARTKENNER:
            print(f'WARNING: EEPROM magic number incorrect ({magic})')
        offset = 4
        properties = dict()
        for fmt, name in EEPROM_MAP:
            field_len = struct.calcsize(fmt)
            bytes = self._read_eeprom(offset, field_len)
            value = struct.unpack(fmt, bytes)
            if fmt[-1] == 's':
                value = value[0].decode('ascii')
            elif len(value) == 1:
                value = value[0]
            # print(f'0x{offset + 0x1400:04x} : {name}')
            offset += field_len
            if name is not None:
                properties[name] = value
        return properties

    def erase(self):
        """erase the module"""
        self._enter_flash_mode()
        self._erase()

    def x(self):
        """hacking"""
        while True:
            self._interface.send(MSG_ping())
            rsp = self._interface.recv(0.02)


def do_upload(module, args):
    """implement the --upload option"""

    mcu_type = int(module.properties['MCU_Type'])

    # detect module type, handle Srecords appropriately
    if mcu_type == 1:
        srecords = HCS08_Srecords(args.upload, args)
    if mcu_type in [6, 8]:
        srecords = S32_Srecords(args.upload, args, mcu_type)
    else:
        raise RuntimeError(f'Unsupported module MCU {mcu_type}')

    module.upload(srecords)

    if not args.console:
        # check for the "I don't like this program" message that
        # may be sent after upload
        msg = interface.recv(0.2)
        if msg is not None:
            try:
                status = MSG_no_program(msg)
                raise RuntimeError('bootloader rejected program, '
                                   + 'may be missing reset vector')
            except MessageError:
                pass


def do_console(interface, args):
    """implement the --console option"""
    line = ''
    while True:
        msg = interface.recv(1)
        if msg is not None:
            try:
                status = MSG_no_program(msg)
                raise RuntimeError('bootloader rejected program, '
                                   + 'may be missing reset vector')
            except MessageError:
                pass
            try:
                status = MSG_ack(msg)
                raise RuntimeError(f'module reset due to {status.reason}')
            except MessageError:
                pass
            if msg.arbitration_id != CONSOLE_ID:
                print(msg)
            else:
                line += msg.data.decode()
        if line.endswith('\0'):
            print(line)
            line = ''


def do_erase(module, args):
    """implement the --erase option"""
    module.erase()


def do_eeprom_dump(module, args):
    """implement the --dump-eeprom option"""
    contents = module.raw_properties
    print(contents)


def do_eeprom_decode(module, args):
    """implement the --decode-eeprom option"""
    properties = module.properties
    for name, value in properties.items():
        print(f'{name:<30} {value}')


def do_print_hcs08_srecords(srec_file, args):
    srecords = HCS08_Srecords(srec_file, args)
    for srec in srecords.text_records:
        print(srec)


parser = argparse.ArgumentParser(description='MRS Microplex 7* and CC16 CAN flasher')
parser.add_argument('--interface',
                    type=str,
                    metavar='INTERFACE_NAME',
                    help='interface name or path')
parser.add_argument('--interface-type',
                    type=str,
                    metavar='INTERFACE_TYPE',
                    default='slcan',
                    help='interface type')
parser.add_argument('--interface-power-control',
                    action='store_true',
                    default=True,
                    help='whether the interface supports MJS power control (SLCAN only)')
parser.add_argument('--can-speed',
                    type=int,
                    default=125000,
                    metavar='BITRATE',
                    help='CAN bitrate')
parser.add_argument('--console',
                    action='store_true',
                    help='monitor console messages after upload')
parser.add_argument('--kl15-after-upload',
                    action='store_true',
                    help='turn KL15 on after upload')
parser.add_argument('--power-off',
                    action='store_true',
                    help='turn power off at exit')
parser.add_argument('--verbose',
                    action='store_true',
                    help='print verbose progress information')

actiongroup = parser.add_mutually_exclusive_group(required=True)
actiongroup.add_argument('--upload',
                         type=Path,
                         metavar='SRECORD_FILE',
                         help='S-record file to upload')
actiongroup.add_argument('--erase',
                         action='store_true',
                         help='erase the program')
actiongroup.add_argument('--dump-eeprom',
                         action='store_true',
                         help='dump the contents of the module EEPROM')
actiongroup.add_argument('--decode-eeprom',
                         action='store_true',
                         help='decode the contents of the module EEPROM')
actiongroup.add_argument('--print-fixed-hcs08-srecords',
                         type=Path,
                         metavar='SRECORD_FILE',
                         help='translate an S-record file as it would be for upload to an HCS08 module')
actiongroup.add_argument('--print-fixed-s32k-srecords',
                         type=Path,
                         metavar='SRECORD_FILE',
                         help='translate an S-record file as it would be for upload to an S32K module')


args = parser.parse_args()
interface = None
if args.verbose:
    def log(msg):
        print(msg)
else:
    def log(msg):
        pass
try:
    if args.print_fixed_hcs08_srecords is not None:
        do_print_hcs08_srecords(args.print_fixed_hcs08_srecords, args)
    elif args.print_fixed_s32k_srecords is not None:
        do_print_s32k_srecords(args.print_fixed_s32k_srecords, args)
    else:
        if args.interface is None:
            raise RuntimeError("--interface not specified")
        interface = CANInterface(args)
        module_id = interface.detect()
        module = Module(interface, module_id, args)
        if args.upload is not None:
            do_upload(module, args)
            if args.kl15_after_upload:
                interface.set_power_t30_t15()
            if args.console:
                do_console(interface, args)
        elif args.erase:
            do_erase(module, args)
        elif args.dump_eeprom:
            do_eeprom_dump(module, args)
        elif args.decode_eeprom:
            do_eeprom_decode(module, args)
except KeyboardInterrupt:
    pass
if interface is not None:
    interface.set_power_off()
