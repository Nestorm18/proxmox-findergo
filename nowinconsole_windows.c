// nowinconsole_windows.c
// Constructor that runs BEFORE Go's runtime init or main().
// Detaches the process from any inherited console and redirects
// stdout/stderr to NUL so no console window can flash on startup.
#include <windows.h>
#include <stdio.h>

void __cdecl preMainInit(void) {
    // Detach from any inherited console (parent CMD/PowerShell).
    FreeConsole();

    // Open NUL and redirect the standard handles to it.
    HANDLE nul = CreateFileA("NUL", GENERIC_WRITE | GENERIC_READ,
                             FILE_SHARE_WRITE | FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, 0, NULL);
    if (nul != INVALID_HANDLE_VALUE) {
        SetStdHandle(STD_OUTPUT_HANDLE, nul);
        SetStdHandle(STD_ERROR_HANDLE, nul);
        SetStdHandle(STD_INPUT_HANDLE, nul);
    }
}

// Tell the linker to call this before main().
// C initializers run before Go runtime init in cgo builds.
typedef void (*init_func)(void);
#pragma section(".CRT$XIU", read)
__declspec(allocate(".CRT$XIU")) init_func preMainInitPtr = preMainInit;
