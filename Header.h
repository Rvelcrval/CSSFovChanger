#pragma once
#include <Windows.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <stdio.h>

//client.dll + 383F0 - C7 05 CE9D6500 0000F042	- mov[ client.dll + 6921C8 ], 42F00000	{ (120.00),120.00 }
//client.dll + 383FA - C2 0000					- ret 0000								{ 0 }

static BYTE original[ ]  = "\xC2\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC";
static BYTE shellcode[ ] = "\xC7\x05\x48\x68\x97\x79\x00\x00\xF0\x42\xC2\x00\x00";
const BYTE addressOffset = 2;
const BYTE fovOffset = 6;
const UINT32 viewOffset = 0x6921C8;
const UINT32 writeOffset = 0x383F0;

//C7 05 CE9D6500 0000F042 len = 0xA
const UINT32 opCodeLen = 0xA;
const UINT32 viewRelativeOffset = viewOffset - writeOffset - opCodeLen;

constexpr UINT64 FastHash ( const wchar_t* str ) {
	UINT64 hash = 0xcbf29ce484222325ull;
	for ( const wchar_t* c = str; *c; ++c ) {
		hash ^= ((hash << 5) + (*c) + (hash >> 2));
	}
	return hash;
}

inline bool hashcmp ( const wchar_t* a, UINT64 b ) {
	return FastHash ( a ) == b;
}

constexpr UINT64 PROCESS_NAME = FastHash ( L"cstrike_win64.exe" );
constexpr UINT64 DLL_NAME = FastHash ( L"client.dll" );