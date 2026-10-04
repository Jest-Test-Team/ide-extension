// Rust ETW/WFP agent using the `windows` crate (intentionally flawed fixture).
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Diagnostics::Etw::*;

pub fn open_engine() -> HANDLE {
    let mut engine = HANDLE::default();
    let _ = unsafe { FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, &mut engine) };
    engine
}

pub fn consume(log: &mut EVENT_TRACE_LOGFILEW) {
    let handle = unsafe { OpenTraceW(log) };
    unsafe { CloseTrace(handle) };
}
