/*
 * lpc11c24 SLCAN-based programmer for MRS Microplex controllers.
 *
 * Set up to run on the Olimex LPC-P11C24 board, with a ULN2003
 * spanning the P2_0 to GND30 pads in the perf area.
 *
 * The driver connected to P2_6 in turn drives a relay switching
 * T30 to the Microplex unit.
 *
 * Board Note: do not jump RST_E, as this prevents the board from
 *             booting correctly. Upload must be achieved by
 *             manually resetting the board.
 *
 * The MRS programmer is capable of switching both T30 and T15, but
 * their software doesn't seem to support it. The only way to recover
 * a bricked module, or one with firmware that doesn't support their
 * update protocol, is to catch it in the bootloader immediately
 * after power-on.
 *
 */

#include <stdio.h>
#include <can_rom.h>
#include <etl.h>
#include <etl/scheduler.h>
#include <pin.h>
#include <uart.h>
#include <timer.h>

#include <debug.h>

#include "SerialTask.h"
#include "CANTask.h"
#include "board.h"

void
board_init(void)
{
    // UART
    P1_7_TXD.configure();
    P1_6_RXD.configure();
    UART0.configure(115200);

    // LED GPIOs
    LED1.configure(Gpio::Output, Pin::PushPull);
    LED2.configure(Gpio::Output, Pin::PushPull);
    LED1 << LED_OFF;
    LED2 << LED_OFF;

    // Relay control
    T30_RELAY.configure(Gpio::Output, Pin::PushPull);
    T30_RELAY << RELAY_OFF;
}

class Scheduler : public etl::scheduler<etl::scheduler_policy_sequential_single, 2> {};

extern "C"
void
main(void)
{
    Scheduler   scheduler;

    scheduler.add_task(serial_task);
    scheduler.add_task(can_task);

    can_task.reinit(CAN_ROM::BR_125000);

    debug("start");
    scheduler.start();
}