/*
 * CAN receive task
 */

#include <stdint.h>
#include <can_rom.h>
#include <etl/task.h>

class CANTask : public etl::task
{
public:
    CANTask() : task(1) {}
    void                reinit(CAN_ROM::Bitrate);
    void                open() { _open = true; }
    void                close() { _open = false; }
    virtual uint32_t    task_request_work() const override final;
    virtual void        task_process_work() override final;

    void                report_message(CAN_ROM::Message msg);

private:
    bool                _open;
};

extern CANTask can_task;
