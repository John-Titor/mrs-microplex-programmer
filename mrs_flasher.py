#!python3
#
# Flash an MRS Microplex 7* device.
#
# Should work with any CAN adapter supported by python-can, but
# optimised for use with a homebrew adapter that supports power
# control.
#
# (The MRS adapter has the ability to switch T30 and T15, but
#  their software doesn't appear to actually exploit it as a way
#  of recovering bricked units...)
#

import argparse
import struct
import time
from pathlib import Path
import can

ACK_ID = 0x1ffffff0
CMD_ID = 0x1ffffff1
RSP_ID = 0x1ffffff2
SREC_ID = 0x1ffffff3
DATA_ID = 0x1ffffff4
CONSOLE_ID = 0x1ffffffe
MJS_POWER_ID = 0x0fffffff


EEPROM_STARTKENNER = 1331
EEPROM_MAP = [
    # (format, name)
    # ('2B' '??'),
    # ('>H' 'Startkenner'),
    ('>I',  'Seriennummer'),
    ('12s', 'Teilenummer'),
    ('12s', 'Zeichnungsnummer'),
    ('20s', 'Bezeichnung'),
    ('8s',  'Fertigungsauftrag'),
    ('8s',  'Pruefdatum'),
    ('>H',  'HW_Version'),
    ('B',   'ResetCounter'),
    ('>H',  'Library_Version'),
    ('5B',  'ResetReasonCounter'),
    ('B',   'MCU_Type'),
    ('B',   'HW_CAN_Active'),
    ('3B',  'Bootloader_Werksdaten_Reserve1'),
    ('>H',  'Bootloader_Version'),
    ('>H',  'PROG_Status'),
    ('>H',  'Portbyte1'),
    ('>H',  'Portbyte2'),
    ('>H',  'Baudrate_Bootloader1'),
    ('>H',  'Baudrate_Bootloader2'),
    ('B',   'Bootloader_ID_ext'),
    ('>I',  'Bootloader_ID'),
    ('B',   'Bootloader_ID_CRC'),
    ('B',   'Bootloader_ID_Kopie_ext'),
    ('>I',  'Bootloader_ID_Kopie'),
    ('B',   'Bootloader_ID_Kopie_CRC'),
    ('20s', 'SW_Version'),
    ('30s', 'Modulname'),
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
    _format = '>HBBH'

    def __init__(self, module_id):
        super().__init__(CMD_ID,
                         0x2010,
                         0,
                         0,
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
    _format = '>BBBHBH'
    _filter = [(False, 0),
               (True, 0),
               (True, 0),
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
        (self.reason_code, _, _,
         self.module_id, self.status_code, self.sw_version) = self._values
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
    _format = '>HBBHH'
    _filter = [(True, 0x2110),
               (True, 0),
               (True, 0),
               (False, 0),
               (False, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, _, _, self.module_id, self.sw_version) = self._values


class MSG_program_nak(RXMessage):
    """
    Response sent to MSG_program when the app is running.
    Module reboots after sending this message (and sends MSG_ack
    with reason='reboot'), apparently into the bootloader.
    """
    _format = '>HBBHH'
    _filter = [(True, 0x2fff),
               (True, 0),
               (True, 0),
               (False, 0),
               (False, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, _, _, self.module_id, _) = self._values


class MSG_program_ack(RXMessage):
    """response sent to MSG_program when running the bootloader"""
    _format = '>HBBHH'
    _filter = [(True, 0x2100),
               (True, 0),
               (True, 0),
               (False, 0),
               (False, 0)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)
        (_, _, _, self.module_id, _) = self._values


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
               (True, 0),
               (True, 1)]

    def __init__(self, raw):
        super().__init__(expected_id=RSP_ID,
                         raw=raw)


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
        self.send(MSG_mjs_power(False, False))

    def set_power_t30(self):
        self.send(MSG_mjs_power(True, False))

    def set_power_t30_t15(self):
        self.send(MSG_mjs_power(True, True))

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
                                  'from module: {rsp}')
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


class Srecords(object):
    def __init__(self, path, args):
        try:
            with path.open() as f:
                lines = f.readlines()
        except Exception as e:
            raise RuntimeError(f'could not read S-records from {path}')
        self.lines = list()
        seen_s9 = False
        # preprocess into a form ready for sending
        for line in lines:
            if line[0] != 'S':
                raise RuntimeError(f'malformed S-record: {line}')
            if line[1] == '9':
                # SDCC always generates an all-zeroes entrypoint
                line = "S9032200DA"
                seen_s9 = True
            elif line[1] != '1':
                # ignore anything other than S1 and S9 records
                continue
            else:
                if seen_s9:
                    raise RuntimeError('S9 record must be last in the file')

            # verify that the address range is writable
            count = int(f'0x{line[2:4]}', 16) - 3
            address = int(f'0x{line[4:8]}', 16)
            end = address + count
            if (address >= 0x2200) and (end <= 0xaf7b):
                pass
            elif (address >= 0xaf80) and (end <= 0xbdff):
                pass
            else:
                # silently discard this, as SDCC etc. will emit vectors
                # that can't be programmed
                continue

            # first two bytes to send are ascii, remainder are literals
            self.lines.append(bytearray(line[0:2], 'ascii')
                              + bytes.fromhex(line[2:]))


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
                progress = MSG_progress(rsp)
            except MessageError as e:
                raise ModuleError(f'got unexpected message {rsp} '
                                  f'instead of progress')
            self._print_progress(title, progress.limit, progress.progress)
            if progress.progress == progress.limit:
                break

    def _erase(self):
        """erase the currently-selected module"""
        self._interface.send(MSG_erase())
        self._erase_progress("ERASE ")
        self._erase_progress("ERASE2")
        rsp = self._interface.recv(2)
        if rsp is None:
            raise ModuleError('did not see expected module '
                              'erase completed message')
        try:
            progress = MSG_erase_done(rsp)
        except MessageError as e:
            raise ModuleError(f'got unexpected message {rsp} '
                              f'instead erase done')

    def _program(self, srecords):
        """flash srecords to the currently-selected module"""
        progress = 1
        for srec in srecords.lines:
            for index in range(0, len(srec), 8):
                rsp = self._cmd(MSG_srecord(srec[index:index+8]))
            if rsp is None:
                raise ModuleError(f'timed out waiting for response')

            self._print_progress("FLASH", len(srecords.lines), progress)
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

    def get_eeprom(self):
        """get raw EEPROM contents"""
        self._select()
        return self._read_eeprom(0, 0x800)

    def get_eeprom_properties(self):
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
            print(f'0x{offset + 0x1400:04x} : {name}')
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


def do_upload(interface, args):
    """implement the --upload option"""
    srecords = Srecords(args.upload, args)
    module_id = interface.detect()
    module = Module(interface, module_id, args)
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


def do_erase(interface, args):
    """implement the --erase option"""
    module_id = interface.detect()
    module = Module(interface, module_id, args)
    module.erase()


def do_eeprom_dump(interface, args):
    """implement the --dump-eeprom option"""
    module_id = interface.detect()
    module = Module(interface, module_id, args)
    contents = module.get_eeprom()
    print(contents)


def do_eeprom_decode(interface, args):
    """implement the --decode-eeprom option"""
    module_id = interface.detect()
    module = Module(interface, module_id, args)
    properties = module.get_eeprom_properties()
    for name, value in properties.items():
        print(f'{name:<30} {value}')


def do_x(interface, args):
    id = interface.detect()
    print(f'Found {id}')
    time.sleep(2)
    do_scan(interface, args)
    interface.set_power(False)


parser = argparse.ArgumentParser(description='MRS Microplex 7* CAN flasher')
parser.add_argument('--interface',
                    type=str,
                    required=True,
                    metavar='INTERFACE_NAME',
                    help='interface name or path')
parser.add_argument('--interface-type',
                    type=str,
                    metavar='INTERFACE_TYPE',
                    default='slcan',
                    help='interface type')
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
actiongroup.add_argument('--x',
                         action='store_true',
                         help='test function')


args = parser.parse_args()
interface = None
if args.verbose:
    def log(msg):
        print(msg)
else:
    def log(msg):
        pass
try:
    interface = CANInterface(args)
    if args.upload is not None:
        do_upload(interface, args)
        if args.kl15_after_upload:
            interface.set_power_t30_t15()
        if args.console:
            do_console(interface, args)
    elif args.erase:
        do_erase(interface, args)
    elif args.dump_eeprom:
        do_eeprom_dump(interface, args)
    elif args.decode_eeprom:
        do_eeprom_decode(interface, args)
    elif args.x:
        do_x(interface, args)
except KeyboardInterrupt:
    pass
if interface is not None:
    interface.set_power_off()
