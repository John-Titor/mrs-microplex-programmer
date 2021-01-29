/*
 * Serial task.
 *
 * Handles received SLCAN commands. 
 *
 * Note: we only implement the commands necessary to support python-can, as
 * that's what the programmer app uses.
 *
 * Responds to:
 *
 * C, O  - select closed / open
 * S3, S4, S5, S6, S8 - 100/125/250/500/1000kHz CAN bitrate
 * tiiiLDDDDDDDDDDDDDDDD - send regular CAN frame
 * TiiiiiiiiLDDDDDDDDDDDDDDDD - send extended-id CAN frame
 * V, N - get version, serial number
 *
 * Reports:
 *
 * tiiiLDDDDDDDDDDDDDDDD - received regular CAN frame
 * TiiiiiiiiLDDDDDDDDDDDDDDDD - received extended-id CAN frame
 * <CR> or <BEL> - success / error for an issued command
 *
 */

#include <debug.h>
#include <etl/string_view.h>
#include <uart.h>

#include "SerialTask.h"
#include "CANTask.h"
#include "board.h"

SerialTask serial_task;

namespace {
    template<typename T>
    bool
    from_hex(const etl::istring &str, unsigned index, unsigned count, T &val)
    {
        val = 0;

        while (count--) {
            auto c = str[index++];
            val <<= 4;
            switch (c) {
            case '0'...'9':
                val += c - '0';
                break;
            case 'a'...'f':
                val += c - 'a' + 10;
                break;
            case 'A'...'F':
                val += c - 'A' + 10;
                break;
            default:
                return false;
            }
        }
        return true;
    }

    bool
    cmd_version(const etl::istring &str)
    {
        UART0.send("0101");
        return true;
    }

    bool
    cmd_serial(const etl::istring &str)
    {
        UART0.send("N0001");
        return true;
    }

    bool
    cmd_speed(const etl::istring &str)
    {
        switch(str[1]) {
        case '3':
            can_task.reinit(CAN_ROM::BR_100000);
            break;
        case '4':
            can_task.reinit(CAN_ROM::BR_125000);
            break;
        case '5':
            can_task.reinit(CAN_ROM::BR_250000);
            break;
        case '6':
            can_task.reinit(CAN_ROM::BR_500000);
            break;
        case '8':
            can_task.reinit(CAN_ROM::BR_1000000);
            break;
        default:
            return false;
        }
        return true;
    }

    bool
    cmd_open(const etl::istring &str)
    {
        can_task.open();
        return true;
    }

    bool
    cmd_close(const etl::istring &str)
    {
        can_task.close();
        return true;
    }

    bool
    cmd_send_regular(const etl::istring &str)
    {
        CAN_ROM::Message msg;
        uint32_t id;

        msg.extended = 0;
        msg.rtr = 0;
        if (!from_hex(str, 1, 3, id)
            || !from_hex(str, 4, 1, msg.dlc)) {
            return false;
        }
        msg.id = id;
        for (auto i = 0; i < msg.dlc; i++) {
            if (!from_hex(str, 5 + 2 * i, 2, msg.data[i])) {
                return false;
            }
        }
        CAN_ROM::send(msg);
        return true;
    }

    bool
    cmd_send_extended(const etl::istring &str)
    {
        CAN_ROM::Message msg;
        uint32_t id;

        msg.extended = 1;
        msg.rtr = 0;
        if (!from_hex(str, 1, 8, id)
            || !from_hex(str, 9, 1, msg.dlc)) {
            return false;
        }
        msg.id = id;
        for (auto i = 0; i < msg.dlc; i++) {
            if (!from_hex(str, 10 + 2 * i, 2, msg.data[i])) {
                return false;
            }
        }
        // handle internal-only commands here
        if ((msg.id == 0x0fffffff) && (msg.dlc == 1)) {
            T30_RELAY << ((msg.data[0] & 1) ? RELAY_ON : RELAY_OFF);
        } else {
            CAN_ROM::send(msg);
        }
        return true;
    }

    struct {
        char        cmd;
        bool        (*handler)(const etl::istring &str);
    } dispatch[] = {
        {'V',       cmd_version},
        {'N',       cmd_serial},
        {'S',       cmd_speed},
        {'O',       cmd_open},
        {'C',       cmd_close},
        {'t',       cmd_send_regular},
        {'T',       cmd_send_extended},
    };
}

uint32_t
SerialTask::task_request_work() const
{
    return UART0.recv_available() ? 1 : 0;
}

void
SerialTask::task_process_work()
{
    uint8_t c;

    while (UART0.recv(c)) {
        switch (c) {
        case '\r':
        case '\n':
            if (_input_buffer.size() > 0) {
                _process_command();
                _input_buffer.clear();
            }
            break;
        case 'a'...'z':
        case 'A'...'Z':
        case '0'...'9':
            _input_buffer.push_back(c);
            break;
        default:
            break;
        }
    }
}

void
SerialTask::_process_command()
{
    // iterate handlers
    for (auto dent : dispatch) {
        // if the handler wants this command...
        if (dent.cmd == _input_buffer[0]) {
            // get a view over the remainder of the command
            if (dent.handler(_input_buffer)) {
                UART0.send('\r');
                LED2 << LED_OFF;
            } else {
                UART0.send('\a');
                LED2 << LED_ON;
            }
            return;
        }
    }
    UART0.send('\a');
}

