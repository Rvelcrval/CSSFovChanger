#include "Header.h"

HMODULE FindTargetModule ( HANDLE targetProcess ) {
    HMODULE modules[ 1024 ] = { 0 };
    DWORD numModules = 0;

    if ( !EnumProcessModulesEx ( targetProcess, modules, sizeof ( modules ), &numModules, LIST_MODULES_ALL ) )
        exit ( 1 );

    for ( DWORD i = 0; i < numModules; i++ ) {
        TCHAR moduleName[ MAX_PATH ];
		if ( GetModuleBaseName ( targetProcess, modules[ i ], moduleName, MAX_PATH ) &&
			 hashcmp ( (const wchar_t*)moduleName, DLL_NAME ) )
			return modules[ i ];
    }
    exit ( 2 );
}

DWORD FindTargetProcessId ( ) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof ( PROCESSENTRY32 );

    HANDLE snapshot = CreateToolhelp32Snapshot ( TH32CS_SNAPPROCESS, 0 );
    if ( snapshot == INVALID_HANDLE_VALUE )
        exit ( 3 );

    Process32First ( snapshot, &processEntry );
    do {
		if ( hashcmp ( (const wchar_t*)processEntry.szExeFile, PROCESS_NAME ) ) {
			CloseHandle ( snapshot );
            return processEntry.th32ProcessID;
		}
	} while ( Process32Next ( snapshot, &processEntry ) );

    CloseHandle ( snapshot );
    exit ( 4 );
}

int main ( int argc, char* argv[ ] ) {
	UINT32* address = (UINT32*)(shellcode + addressOffset);
	float* fov = (float*)(shellcode + fovOffset);

	if ( argc > 1 )
		*fov = atof ( argv[ 1 ] );

    HANDLE targetProcess = OpenProcess ( PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION, FALSE, FindTargetProcessId ( ) );
    HMODULE targetModule = FindTargetModule ( targetProcess );

    UINT64 modAddress = UINT64 ( targetModule );
    *address = viewRelativeOffset;
    if( *fov == 0.f )
        WriteProcessMemory ( targetProcess, LPVOID ( modAddress + writeOffset ), (LPVOID)original, sizeof ( original ) - 1, NULL );
    else
        WriteProcessMemory ( targetProcess, LPVOID ( modAddress + writeOffset ), (LPVOID)shellcode, sizeof ( shellcode ) - 1, NULL );
    CloseHandle ( targetProcess );

	return 0;
}