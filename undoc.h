#ifndef _UNDOC_USERMODE
#ifndef _UNDOC_KERNELMODE
#error "Hey you guy,which mode are you in? #define _UNDOC_USERMODE <OR> #define _UNDOC_KERNELMODE"
#endif
#endif

typedef unsigned short WORD;
typedef UCHAR BYTE;
typedef ULONG DWORD;

//////////////////////////////////////////////////////////////////////////
#ifdef _UNDOC_USERMODE
//////////////////////////////////////////////////////////////////////////
typedef LONG NTSTATUS;

#define IN
#define OUT
#define NTAPI __stdcall
#define MAXIMUM_FILENAME_LENGTH 256

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID,*PCLIENT_ID;

typedef LONG KPRIORITY;

typedef enum _KWAIT_REASON {
    Executive,
	FreePage,
	PageIn,
	PoolAllocation,
	DelayExecution,
	Suspended,
	UserRequest,
	WrExecutive,
	WrFreePage,
	WrPageIn,
	WrPoolAllocation,
	WrDelayExecution,
	WrSuspended,
	WrUserRequest,
	WrEventPair,
	WrQueue,
	WrLpcReceive,
	WrLpcReply,
	WrVirtualMemory,
	WrPageOut,
	WrRendezvous,
	Spare2,
	Spare3,
	Spare4,
	Spare5,
	Spare6,
	WrKernel,
	MaximumWaitReason
} KWAIT_REASON;


typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    PWSTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;
#define UNICODE_NULL ((WCHAR)0) // winnt
/*
typedef struct _IO_COUNTERS {
    ULONGLONG  ReadOperationCount;
    ULONGLONG  WriteOperationCount;
    ULONGLONG  OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS;
typedef IO_COUNTERS *PIO_COUNTERS;*/

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES,*POBJECT_ATTRIBUTES;

//////////////////////////////////////////////////////////////////////////
#endif //_UNDOC_USERMODE
//////////////////////////////////////////////////////////////////////////


extern "C" {

PVOID 
NTAPI 
RtlImageDirectoryEntryToData(
	PVOID ImageBase,
	BOOLEAN MappedAsImage,
	USHORT DirectoryEntry,
	PULONG Size);

PIMAGE_NT_HEADERS 
NTAPI 
RtlImageNtHeader(
	PVOID ImageBase
	);


#ifdef _UNDOC_USERMODE

typedef void (__stdcall*PNormApcRoutine)(
	IN PVOID NormalContext, 
    IN PVOID SystemArgument1, 
    IN PVOID SystemArgument2
    );

NTSTATUS
NTAPI
ZwQueueApcThread(
	IN HANDLE hThread,
	IN PNormApcRoutine ApcNormalRoutine, 
	IN ULONG ApcNormalContext, 
	IN ULONG ApcArg1,
	IN ULONG ApcArg2);
#endif //_UNDOC_USERMODE

#define SE_MACHINE_ACCOUNT_PRIVILEGE      (6L)
#define SE_TCB_PRIVILEGE                  (7L)
#define SE_SECURITY_PRIVILEGE             (8L)
#define SE_TAKE_OWNERSHIP_PRIVILEGE       (9L)
#define SE_LOAD_DRIVER_PRIVILEGE          (10L)
#define SE_SYSTEM_PROFILE_PRIVILEGE       (11L)
#define SE_SYSTEMTIME_PRIVILEGE           (12L)
#define SE_PROF_SINGLE_PROCESS_PRIVILEGE  (13L)
#define SE_INC_BASE_PRIORITY_PRIVILEGE    (14L)
#define SE_CREATE_PAGEFILE_PRIVILEGE      (15L)
#define SE_CREATE_PERMANENT_PRIVILEGE     (16L)
#define SE_BACKUP_PRIVILEGE               (17L)
#define SE_RESTORE_PRIVILEGE              (18L)
#define SE_SHUTDOWN_PRIVILEGE             (19L)
#define SE_DEBUG_PRIVILEGE                (20L)
#define SE_AUDIT_PRIVILEGE                (21L)
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE   (22L)
#define SE_CHANGE_NOTIFY_PRIVILEGE        (23L)
#define SE_REMOTE_SHUTDOWN_PRIVILEGE      (24L)
#define SE_UNDOCK_PRIVILEGE               (25L)
#define SE_SYNC_AGENT_PRIVILEGE           (26L)
#define SE_ENABLE_DELEGATION_PRIVILEGE    (27L)
#define SE_MANAGE_VOLUME_PRIVILEGE        (28L)
#define SE_MAX_WELL_KNOWN_PRIVILEGE       (SE_MANAGE_VOLUME_PRIVILEGE)

//////////////////////////////////////////////////////////////////////////
//RtlAdjustPriviledge in lib ntdll.dll
//Privilege =SE_XXXX_PRIVILEGE
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
RtlAdjustPrivilege(
	IN ULONG Privilege,
	IN BOOLEAN bEnable,
	IN BOOLEAN bClient,
	OUT PBOOLEAN WasEnabled
	);
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
ZwAlertThread(
	IN HANDLE hThread
	);

#pragma warning(disable:4200)

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef enum {
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition,
	StateUnknown
} THREAD_STATE;

typedef struct _SYSTEM_MODULE { //SystemModuleInformation
	ULONG                Reserved1;
	ULONG                Reserved2;
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	BYTE                 Name[MAXIMUM_FILENAME_LENGTH];	
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_THREADS {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	THREAD_STATE State;
	KWAIT_REASON WaitReason;
} SYSTEM_THREADS, *PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES { // Information Class SystemProcessInformation
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName; 
	KPRIORITY BasePriority;
	ULONG ProcessId;            
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters; // Windows 2000 only
	SYSTEM_THREADS Threads[0];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE { //SystemHandleInformation
    ULONG            ProcessId;
    UCHAR            ObjectTypeNumber;
    UCHAR            Flags;
    USHORT           Handle;
    PVOID            Object;
    ACCESS_MASK      GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

#pragma pack(push,4)
typedef struct _EXHANDLE {
	union{
		struct{
			ULONG unused1:2;
			ULONG EntryLevel3:9;
			ULONG EntryLevel2:9;
			ULONG EntryLevel1:9;
			ULONG unused2:3;
		}wxp;

		struct{
			ULONG unused1:2;
			ULONG EntryLevel3:8;
			ULONG EntryLevel2:8;
			ULONG EntryLevel1:8;
			ULONG unused2:6;
		}w2k;
		HANDLE Handle;
	};
}EXHANDLE,*PEXHANDLE;
#pragma pack(pop)

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG			HandlesCount;
	SYSTEM_HANDLE	Handles[0];
}SYSTEM_HANDLE_INFORMATION,*PSYSTEM_HANDLE_INFORMATION;

typedef struct _LDR_MODULE  // PEB -> InXXXOrderModuleList; NOT TESTED YET
{
    LIST_ENTRY        InLoadOrderModuleList;            // +0x00
    LIST_ENTRY        InMemoryOrderModuleList;          // +0x08
    LIST_ENTRY        InInitializationOrderModuleList;  // +0x10
    PVOID             BaseAddress;                      // +0x18
    PVOID             EntryPoint;                       // +0x1c
    ULONG             SizeOfImage;                      // +0x20
    UNICODE_STRING    FullDllName;                      // +0x24
    UNICODE_STRING    BaseDllName;                      // +0x2c
    ULONG             Flags;                            // +0x34
    SHORT             LoadCount;                        // +0x38
    SHORT             TlsIndex;                         // +0x3a
    LIST_ENTRY        HashTableEntry;                   // +0x3c
    ULONG             TimeDateStamp;                    // +0x44
	// +0x48
} LDR_MODULE, *PLDR_MODULE;

typedef struct _LDR_DATA_TABLE_ENTRY { //Windows XP SP2 for PsLoadedModuleList
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
    };
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#pragma warning(default:4200)

NTSYSAPI 
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID               SystemInformation,
	IN ULONG                SystemInformationLength,
	OUT PULONG              ReturnLength OPTIONAL
	);

NTSYSAPI 
NTSTATUS
NTAPI
ZwSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID                SystemInformation,
    IN ULONG                SystemInformationLength
    );

NTSTATUS
ZwTerminateProcess(
    IN  HANDLE ProcessHandle OPTIONAL,
    IN  NTSTATUS ExitStatus
    );


NTSYSCALLAPI
NTSTATUS
NTAPI
ZwOpenProcess (
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL
);





//////////////////////////////////////////////////////////////////////////
//	KERNEL MODE ONLY
//////////////////////////////////////////////////////////////////////////
#ifdef _UNDOC_KERNELMODE
NTSTATUS
ObOpenObjectByPointer(
    IN  PVOID Object,
    IN  ULONG HandleAttributes,
    IN  PACCESS_STATE PassedAccessState OPTIONAL,
    IN  ACCESS_MASK DesiredAccess,
    IN  POBJECT_TYPE ObjectType,
    IN  KPROCESSOR_MODE AccessMode,
    OUT PHANDLE Handle
    );

extern PUSHORT NtBuildNumber;

typedef struct _SERVICE_DESCRIPTOR_TABLE
{
	PVOID   ServiceTableBase;
	PULONG  ServiceCounterTableBase;
	ULONG   NumberOfService;
	ULONG   ParamTableBase;
}SERVICE_DESCRIPTOR_TABLE,*PSERVICE_DESCRIPTOR_TABLE;

extern PSERVICE_DESCRIPTOR_TABLE  KeServiceDescriptorTable;

typedef struct _EX_PUSH_LOCK{
	union{
		struct  
		{
			ULONG Waiting:1;
			ULONG Exclusive:1;
			ULONG Shared:30;
		};
		ULONG Value;
		PVOID Ptr;
	};
}EX_PUSH_LOCK,*PEX_PUSH_LOCK;

typedef HANDLE_TRACE_DEBUG_INFO,*PHANDLE_TRACE_DEBUG_INFO; // Useless thing?

typedef struct _HANDLE_TABLE_ENTRY{
	ULONG pObjectWithMask;
	ULONG GrantedAccess;
}HANDLE_TABLE_ENTRY,*PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE{
	union{
		struct{
			ULONG TableCode;
			PEPROCESS QuotaProcess;
			ULONG UniqueProcessId;
			EX_PUSH_LOCK HandleTableLock;
			LIST_ENTRY HandleTableList;
			EX_PUSH_LOCK HandleContentionEvent;
			PHANDLE_TRACE_DEBUG_INFO DebugInfo;
			ULONG ExtraInfoPages;
			ULONG FirstFree;
			ULONG LastFree;
			ULONG NextHandleNeedingPool;
			ULONG HandleCount;
			ULONG Flags;
		}wxp;
	};
}HANDLE_TABLE,*PHANDLE_TABLE;


#define OB_FLAG_CREATE_INFO 0x01 // has OBJECT_CREATE_INFO
#define OB_FLAG_KERNEL_MODE 0x02 // created by kernel
#define OB_FLAG_CREATOR_INFO 0x04 // has OBJECT_CREATOR_INFO
#define OB_FLAG_EXCLUSIVE 0x08 // OBJ_EXCLUSIVE
#define OB_FLAG_PERMANENT 0x10 // OBJ_PERMANENT
#define OB_FLAG_SECURITY 0x20 // has security descriptor
#define OB_FLAG_SINGLE_PROCESS 0x40 // no HandleDBList

typedef struct _OBJECT_CREATOR_INFO{
	LIST_ENTRY ObjectList; // OBJECT_CREATOR_INFO
	HANDLE UniqueProcessId;
	WORD Reserved1;
	WORD Reserved2;
}OBJECT_CREATOR_INFO,*POBJECT_CREATOR_INFO;

typedef QUOTA_BLOCK,*PQUOTA_BLOCK;

typedef struct _OBJECT_HEADER
{
	DWORD PointerCount; // number of references
	union{
		DWORD HandleCount; // number of open handles
		PVOID NextToFree;
	};
	POBJECT_TYPE ObjectType;
	BYTE NameOffset; // -> OBJECT_NAME
	BYTE HandleDBOffset; // -> OBJECT_HANDLE_DB
	BYTE QuotaChargesOffset; // -> OBJECT_QUOTA_CHARGES
	BYTE ObjectFlags; // OB_FLAG_*
	union
	{ // OB_FLAG_CREATE_INFO ? ObjectCreatorInfo : QuotaBlock
		PQUOTA_BLOCK QuotaBlock;
		POBJECT_CREATOR_INFO ObjectCreatorInfo;
	};
	PSECURITY_DESCRIPTOR SecurityDescriptor;
}OBJECT_HEADER,* POBJECT_HEADER;


typedef struct _EPROCESS_EXTRACT
{
	ULONG UniqueProcessID;
	ULONG InheritedFromUniqueProcessId;
	PPEB pPeb;
	PHANDLE_TABLE ObjectTable;
	LPSTR ImageFileName;
	PEPROCESS Forwarder;
	PEPROCESS Backwarder;
}EPROCESS_EXTRACT,*PEPROCESS_EXTRACT;

//!!!!!COPY THE CODE BELOW!!!!!//
NTSTATUS ExtractEProcess(PEPROCESS pEP,PEPROCESS_EXTRACT pEE);
/*
NTSTATUS ExtractEProcess(PEPROCESS pEP,PEPROCESS_EXTRACT pEE)
{
	PLIST_ENTRY l;
	switch(*NtBuildNumber)
	{
	case 2600: //Windows XP
		pEE->ImageFileName=(LPSTR)((ULONG)pEP)+0x174;
		pEE->pPeb=(PPEB)(*(ULONG*)(((ULONG)pEP)+0x1B0));
		pEE->UnipueProcessID=*(ULONG*)(((ULONG)pEP)+0x084);
		pEE->InheritedFromUniqueProcessId=*(ULONG*)(((ULONG)pEP)+0x14c);
		pEE->ObjectTable=(PHANDLE_TABLE)(*(ULONG*)(((ULONG)pEP)+0x0c4));
		l=(PLIST_ENTRY)(((ULONG)pEP)+0x088);
		pEE->Forwarder=(PEPROCESS)(((ULONG)l->Flink)-0x88);
		pEE->Backwarder=(PEPROCESS)(((ULONG)l->Blink)-0x88);
		return STATUS_SUCCESS;
	default:
		return STATUS_NOT_IMPLEMENTED;
	}
}*/


NTSTATUS
PsLookupProcessByProcessId(
    IN  HANDLE ProcessId,
    OUT PEPROCESS *Process
    );

NTSTATUS
ZwUnloadDriver(
	IN  PUNICODE_STRING DriverServiceName
	);


#endif //_UNDOC_KERNELMODE
} // extern "C"