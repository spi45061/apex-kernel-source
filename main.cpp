

#include "driver/xorstr.h"
#include "system/funcs.h"
#include "driver/include.h"
#include "core/hook.h"
#include <intrin.h>

void CopyList(IN PLIST_ENTRY Original,
	IN PLIST_ENTRY Copy,
	IN KPROCESSOR_MODE Mode)
{
	if (IsListEmpty(&Original[Mode]))
	{
		InitializeListHead(&Copy[Mode]);
	}
	else
	{
		Copy[Mode].Flink = Original[Mode].Flink;
		Copy[Mode].Blink = Original[Mode].Blink;
		Original[Mode].Flink->Blink = &Copy[Mode];
		Original[Mode].Blink->Flink = &Copy[Mode];
	}
}

void
MoveApcState(PKAPC_STATE OldState,
	PKAPC_STATE NewState)
{
	RtlCopyMemory(NewState, OldState, sizeof(KAPC_STATE));

	CopyList(OldState->ApcListHead, NewState->ApcListHead, KernelMode);
	CopyList(OldState->ApcListHead, NewState->ApcListHead, UserMode);
}

uintptr_t OldProcess;
void AttachProcess(PEPROCESS NewProcess)
{
	PKTHREAD Thread = KeGetCurrentThread();

	PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98); // 0x98 = _KTHREAD::ApcState

	if (*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) == NewProcess) // 0x20 = _KAPC_STATE::Process
		return;

	if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) != 0)) // 0x24a = _KTHREAD::ApcStateIndex
	{
		KeBugCheck(INVALID_PROCESS_ATTACH_ATTEMPT);
		return;
	}

	MoveApcState(ApcState, *(PKAPC_STATE*)(uintptr_t(Thread) + 0x258)); // 0x258 = _KTHREAD::SavedApcState

	InitializeListHead(&ApcState->ApcListHead[KernelMode]);
	InitializeListHead(&ApcState->ApcListHead[UserMode]);

	OldProcess = *(uintptr_t*)(uintptr_t(ApcState) + 0x20);

	*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) = NewProcess; // 0x20 = _KAPC_STATE::Process
	*(UCHAR*)(uintptr_t(ApcState) + 0x28) = 0;				// 0x28 = _KAPC_STATE::InProgressFlags
	*(UCHAR*)(uintptr_t(ApcState) + 0x29) = 0;				// 0x29 = _KAPC_STATE::KernelApcPending
	*(UCHAR*)(uintptr_t(ApcState) + 0x2a) = 0;				// 0x2a = _KAPC_STATE::UserApcPendingAll

	*(UCHAR*)(uintptr_t(Thread) + 0x24a) = 1; // 0x24a = _KTHREAD::ApcStateIndex

	auto DirectoryTableBase = *(uint64_t*)(uint64_t(NewProcess) + 0x28);  // 0x28 = _EPROCESS::DirectoryTableBase
	__writecr3(DirectoryTableBase);
}

void DetachProcess()
{
	PKTHREAD Thread = KeGetCurrentThread();
	PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98); // 0x98 = _KTHREAD->ApcState

	if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) == 0)) // 0x24a = KTHREAD->ApcStateIndex
		return;

	if ((*(UCHAR*)(uintptr_t(ApcState) + 0x28)) ||  // 0x28 = _KAPC_STATE->InProgressFlags
		!(IsListEmpty(&ApcState->ApcListHead[KernelMode])) ||
		!(IsListEmpty(&ApcState->ApcListHead[UserMode])))
	{
		KeBugCheck(INVALID_PROCESS_DETACH_ATTEMPT);
	}

	MoveApcState(*(PKAPC_STATE*)(uintptr_t(Thread) + 0x258), ApcState); // 0x258 = _KTHREAD::SavedApcState

	if (OldProcess)
		*(uintptr_t*)(uintptr_t(ApcState) + 0x20) = OldProcess; // 0x20 = _KAPC_STATE::Process

	*(PEPROCESS*)(*(uintptr_t*)(uintptr_t(Thread) + 0x258) + 0x20) = 0; // 0x258 = _KTHREAD::SavedApcState + 0x20 = _KAPC_STATE::Process

	*(UCHAR*)(uintptr_t(Thread) + 0x24a) = 0; // 0x24a = _KTHREAD::ApcStateIndex

	auto DirectoryTableBase = *(uint64_t*)(uint64_t(*(PEPROCESS*)(uintptr_t(ApcState) + 0x20)) + 0x28); // 0x20 = _KAPC_STATE::Process + 0x28 = _EPROCESS::DirectoryTableBase
	__writecr3(DirectoryTableBase);

	if (!(IsListEmpty(&ApcState->ApcListHead[KernelMode])))
	{
		*(UCHAR*)(uint64_t(ApcState) + 0x29) = 1; // 0x29 = _KAPC_STATE::KernelApcPending
	}

	RemoveEntryList(&ApcState->ApcListHead[KernelMode]);

	OldProcess = 0;
}
NTSTATUS find_process(char* process_name, PEPROCESS* process)
{
	PEPROCESS sys_process = PsInitialSystemProcess;
	PEPROCESS curr_entry = sys_process;

	char image_name[15];

	do {
		RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

		if (strstr(image_name, process_name)) {
			DWORD active_threads;
			RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)curr_entry + 0x5f0), sizeof(active_threads));
			if (active_threads) {
				*process = curr_entry;
				return STATUS_SUCCESS;
			}
		}

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
		curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

	} while (curr_entry != sys_process);

	return STATUS_NOT_FOUND;
}
extern "C" NTSTATUS DriverEntry( PDRIVER_OBJECT, PUNICODE_STRING )
{
	PEPROCESS gayf;
	find_process("winlogon.exe", &gayf);

	AttachProcess(gayf);

	uintptr_t win32k = system::get_system_module(XORS(L"win32k.sys"));
	if (!win32k)
	{
		DbgPrintEx(0,0,"win32k.sys not found in system modules, unable to load driver.\n");
		return STATUS_ABANDONED;
	}
	core_hook::fptr_addr = system::find_pattern(win32k, XORS("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x06\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x48"), XORS("xxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxxxxx????xxxxxxx????xxxxxxxxxxxxxxxxxx"));
	if (!core_hook::fptr_addr)
	{
		DbgPrintEx(0, 0, "unable to find target function.\n");
		return STATUS_UNSUCCESSFUL;

	}
	DbgPrintEx(0, 0, "NtUserGetGuiResources: 0x%llx\n", core_hook::fptr_addr);


	//uint32_t core_count = KeQueryActiveProcessorCount(nullptr);

	*(void**)&core_hook::o_function_qword_1 = InterlockedExchangePointer((void**)dereference(core_hook::fptr_addr), (void*)core_hook::hooked_fptr);
	DetachProcess();
	DbgPrintEx(0, 0, "driver successfully loaded.\n");
	return STATUS_SUCCESS;
}