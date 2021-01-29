/*
 * Serial input task
 */

#pragma once

#include <etl/string.h>
#include <etl/task.h>

class SerialTask : public etl::task
{
public:
    SerialTask() : task(1) {}

    virtual uint32_t    task_request_work() const override final;
    virtual void        task_process_work() override final;

private:
    etl::string<40>     _input_buffer;

    void                _process_command();
};

extern SerialTask serial_task;
