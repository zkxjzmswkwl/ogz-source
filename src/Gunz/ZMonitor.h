#pragma once
#include <Windows.h>
#include <ntstatus.h>
#include <winternl.h>

typedef struct _CODEINTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} CODEINTEGRITY_INFORMATION, *PCODEINTEGRITY_INFORMATION;

typedef NTSTATUS(WINAPI* NtQuerySystemInformationProto)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

/// <summary>
/// I typically don't love namespaces, but with multiple developers involved, it's nice to have
/// an explicit "this is a piece of the security checks. Don't touch this" baked into the calls themselves.
///
/// Also, any string literals within these functions should be obfuscated in some way.
/// Bare minimum being xorstr_.
///
/// It might also be worth manually mapping a copy of ntdll into memory and calling the NT* functions via that.
/// Would result in no xrefs leading directly back to these calls.
/// 
/// Additionally, spoofing return addresses wouldn't be a bad idea either.
/// </summary>
namespace SecCheck {
    /// <summary>
    /// We return the value directly as well as assign the return value to the out param.
    /// It takes us 30 seconds, but straying from the 'norm' can often result in footguns for bad actors.
    /// </summary>
    /// <param name="outTestSigningState"></param>
    /// <returns></returns>
    ULONG QueryTestSigningState(OUT ULONG* outTestSigningState);
} // namespace SecCheck