// Real-time ETW consumer (intentionally flawed fixture).
#include <windows.h>
#include <evntrace.h>

static const GUID KernelProcess = {0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

int consume(EVENT_TRACE_PROPERTIES *props, EVENT_TRACE_LOGFILEW *log) {
    TRACEHANDLE session = 0;
    StartTraceW(&session, L"EdrSession", props);
    EnableTraceEx2(session, &KernelProcess, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);
    TRACEHANDLE consumer = OpenTraceW(log);
    if (consumer == INVALID_HANDLE_VALUE) {
        return 1;
    }
    ProcessTrace(&consumer, 1, NULL, NULL);
    return 0;
}
