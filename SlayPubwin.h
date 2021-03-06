// SlayPubwin.h
//
// Generated by C DriverWizard 3.2.0 (Build 2485)
// Requires DDK Only
// File created on 10/14/2008
//
#ifdef __cplusplus
extern "C" {
#endif
#ifndef __SLAYPUBWIN_H__
#define __SLAYPUBWIN_H__

// Memory allocation pool tag
#define SLAYPUBWIN_POOL_TAG 'yalS'

// Make all pool allocations tagged
#undef ExAllocatePool
#define ExAllocatePool(type, size) \
    ExAllocatePoolWithTag(type, size, SLAYPUBWIN_POOL_TAG);

NTSTATUS __stdcall DriverEntry(
    IN  PDRIVER_OBJECT  DriverObject,
    IN  PUNICODE_STRING RegistryPath
    );

VOID __stdcall SlayPubwinUnload(
    IN  PDRIVER_OBJECT  DriverObject
    );

#ifdef __cplusplus
}
#endif

#endif  // __SLAYPUBWIN_H__
