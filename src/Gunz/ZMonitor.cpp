#include "ZMonitor.h"


/// Docs in \ZMonitor.h

namespace SecCheck {
    ULONG QueryTestSigningState(OUT ULONG* outTestSigningState) {
        // TODO: vmp virtualize start
        HMODULE hNtdll = LoadLibraryA("ntdll.dll");  // obfuscate me
        if (!hNtdll) return false;

        auto ntqsiLoc = GetProcAddress(hNtdll, "NtQuerySystemInformation"); // obfuscate me
        auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationProto>(ntqsiLoc);
        if (!NtQuerySystemInformation) {
            FreeLibrary(hNtdll);
            return false;
        }

        CODEINTEGRITY_INFORMATION ciInfo = { 0 };
        ciInfo.Length = sizeof(ciInfo);
        NTSTATUS status = NtQuerySystemInformation(_SYSTEM_INFORMATION_CLASS::SystemCodeIntegrityInformation,
                                                   &ciInfo,
                                                   sizeof(ciInfo),
                                                   nullptr);

        if (!NT_SUCCESS(status)) {
            *outTestSigningState = status;
            FreeLibrary(hNtdll);
            return *outTestSigningState;
        }

        FreeLibrary(hNtdll);
        // Big Rust will have you think this is "dangerous", "unfit for modern computing", and "stupid".
        *outTestSigningState = ciInfo.CodeIntegrityOptions & CODEINTEGRITY_OPTION_TESTSIGN;

        // vmp virtualize end
        return *outTestSigningState;
    }
} // namespace SecCheck