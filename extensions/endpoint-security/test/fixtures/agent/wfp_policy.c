// WFP user-mode policy installer (intentionally flawed fixture).
#include <windows.h>
#include <fwpmu.h>

DWORD install_block_rule(const FWPM_FILTER0 *filter, const FWPM_SUBLAYER0 *sublayer) {
    HANDLE engine = NULL;
    DWORD rc = FwpmEngineOpen0(L"remote-host", RPC_C_AUTHN_WINNT, NULL, NULL, &engine);
    if (rc != ERROR_SUCCESS) {
        return rc;
    }
    FwpmSubLayerAdd0(engine, sublayer, NULL);
    rc = FwpmFilterAdd0(engine, filter, NULL, NULL);
    return rc;
}

DWORD install_with_txn(HANDLE engine, const FWPM_FILTER0 *filter) {
    DWORD rc = FwpmTransactionBegin0(engine, 0);
    if (rc != ERROR_SUCCESS) return rc;
    rc = FwpmFilterAdd0(engine, filter, NULL, NULL);
    if (rc != ERROR_SUCCESS) return rc;
    return FwpmTransactionCommit0(engine);
}
