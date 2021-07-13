#!python3
#
# Flash programmer for various MRS devices.
#
# Should work with any CAN adapter supported by python-can, but
# optimised for use with a homebrew adapter that supports power
# control. 
#
# This can be implemented in enhanced CAN interface firmware,
# e.g. an Arduino or similar with SLCAN firmware and a GPIO
# driving a relay for T30), or with another device on the target
# CAN bus listening for MODULE_POWER_ID and switching module T30
# based on the LSB of byte 0.
#
# If power control is not available, start the script with module
# power off, then turn it on within a few seconds. Unlike the MRS
# flashers which depend on the application participating in
# the reboot-to-flash process, this script captures the module in
# the bootloader immediately out of reset, and so it works even
# if the application is bad.
#
# S-record files for S32K modiles include S0 records denoting the 
# intended target device part / order numbers and hardware 
# revisions, e.g.:
#
# MRS-Check>>>400803,400948,401395,401380,400817,400811,400814,400819,401368<<<B,B1 // V2.6.0.0 Lib-S32K-2.6.0
# MRS-ProgData>>>125 kBit;V0.0.0;CC16WP Application
# MRS-ExtraData>>>1.154.300.00,1.154.211.00,1.154.300.0010,1.154.300.0200,1.154.300.10,1.154.302.00,1.154.302.03,1.154.310.00,1.154.320.00,1.154.330.00,1.154.343.03,1.154.;B,B1;
#
# An S5 record may also be present. These records are never sent to
# the module.
#

import argparse, time
from pathlib import Path

from mrs_srecord import S32K_Srecords, HCS08_Srecords
from mrs_bl_protocol import Interface, Module


def do_upload(module, args):
    """implement the --upload option"""

    # detect module type, handle Srecords appropriately
    mcu_type = module.parameter('MCUType')
    if mcu_type == 1:
        srecords = HCS08_Srecords(args.upload, args)
    elif mcu_type in [6, 8]:
        srecords = S32K_Srecords(args.upload, args, mcu_type)
    else:
        raise RuntimeError(f'Unsupported module MCU {mcu_type}')

    module.upload(srecords)


def do_console(module, args):
    """implement the --console option"""
    line = ''
    while True:
        fragment = module.get_console_data()
        line += bytes(fragment).decode()
        if line.endswith('\0'):
            print(line)
            line = ''


def do_erase(module, args):
    """implement the --erase option"""
    module.erase()


def do_print_parameters(module, args):
    """implement the --print-module_parameters option"""
    for name in module.parameter_names:
        print(f'{name:<30} {module.parameter(name)}')


def do_print_hcs08_srecords(srec_file, args):
    srecords = HCS08_Srecords(srec_file, args)
    for srec in srecords.text_records:
        print(srec)


def do_print_s32k_srecords(srec_file, args):
    srecords = S32K_Srecords(srec_file, args, 6)
    for srec in srecords.text_records:
        print(srec)


parser = argparse.ArgumentParser(description='MRS Microplex 7* and CC16 CAN flasher')
parser.add_argument('--can-speed',
                    type=int,
                    default=500,
                    metavar='BITRATE_KBPS',
                    help='CAN bitrate (kBps')
parser.add_argument('--console-after-upload',
                    action='store_true',
                    help='monitor console messages after upload')
parser.add_argument('--power-cycle-after-upload',
                    action='store_true',
                    help='cycle power and leave KL30 on after upload')
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
actiongroup.add_argument('--console',
                         action='store_true',
                         help='turn on module power and monitor the console')
actiongroup.add_argument('--print-module-parameters',
                         action='store_true',
                         help='print all module parameters')
actiongroup.add_argument('--print-fixed-hcs08-srecords',
                         type=Path,
                         metavar='SRECORD_FILE',
                         help='translate an S-record file as it would be for upload to an HCS08 module')
actiongroup.add_argument('--print-fixed-s32k-srecords',
                         type=Path,
                         metavar='SRECORD_FILE',
                         help='translate an S-record file as it would be for upload to an S32K module')


args = parser.parse_args()
if args.print_fixed_hcs08_srecords is not None:
    do_print_hcs08_srecords(args.print_fixed_hcs08_srecords, args)
elif args.print_fixed_s32k_srecords is not None:
    do_print_s32k_srecords(args.print_fixed_s32k_srecords, args)
else:
    try:
        # find and connect to a module
        interface = Interface(args)
        module_id = interface.detect()
        module = Module(interface, module_id, args)

        # Upload S-records
        if args.upload is not None:
            do_upload(module, args)
            if args.power_cycle_after_upload:
                interface.set_power_off()
                time.sleep(0.25)
                interface.set_power_t30_t15()

            if args.console_after_upload:
                do_console(interface, args)

        # Erase the module
        if args.erase:
            do_erase(module, args)

        # Print module parameters
        if args.print_module_parameters:
            do_print_parameters(module, args)

        # Reset the module and run the console
        # If we don't reset, it will sit for a (long) while in the bootloader
        # after detection before timing out and starting the app. This is faster.
        if args.console:
            interface.set_power_off()
            time.sleep(0.25)
            interface.set_power_t30_t15()
            do_console(interface, args)

    except KeyboardInterrupt:
        pass
