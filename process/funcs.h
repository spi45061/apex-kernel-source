#pragma once
#include "../driver/include.h"



namespace process
{
	PEPROCESS get_by_id(uint32_t pid, NTSTATUS *pstatus = nullptr);
}