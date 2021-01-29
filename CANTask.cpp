/*
 * CAN receive task.
 */

#include <debug.h>
#include <etl/string.h>
#include <uart.h>

#include "CANTask.h"
#include "board.h"

CANTask can_task;

namespace {
    void
    append_hex(etl::istring &str, unsigned len, uint32_t val)
    {
        auto pos = str.size();
        while (len--) {
            auto hb = val & 0xf;
            val >>= 4;
            switch (hb) {
            case (0)...(9):
                str.insert(pos, 1, (char)('0' + hb));
                break;
            case (0xa)...(0xf):
                str.insert(pos, 1, (char)('A' + hb - 0xa));
                break;
            }
        }
    }
}

void
CANTask::reinit(CAN_ROM::Bitrate rate)
{
    CAN_ROM::init(rate);
}

uint32_t
CANTask::task_request_work() const
{
    // need to have space to report the message & a message to report
    return ((UART0.send_space() >= 30) && CAN_ROM::available()) ? 1 : 0;
}

void
CANTask::task_process_work()
{
    CAN_ROM::Message msg;

    LED1 << LED_ON;
    if (CAN_ROM::recv(msg) && _open) {
        report_message(msg);
    }
}

void
CANTask::report_message(CAN_ROM::Message msg)
{
    etl::string<30> str;
    if (msg.extended) {
        str.push_back('T');
        append_hex(str, 8, msg.id);
    } else {
        str.push_back('t');
        append_hex(str, 3, msg.id);
    }
    append_hex(str, 1, msg.dlc);
    for (auto i = 0; i < msg.dlc; i++) {
        append_hex(str, 2, msg.data[i]);
    }
    str.push_back('\r');
    UART0.send(str);
}
