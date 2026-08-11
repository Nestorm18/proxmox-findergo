// nowinconsole_windows.go — runs a Windows console-suppression routine
// at the very start of program init, before Wails / WebView2 can attach
// to or allocate a console.
//
//go:build desktop && windows

package main

/*
#include <windows.h>
#include <stdio.h>

// C constructor: runs before main() and before Go runtime init.
static void __attribute__((constructor)) suppress_console(void) {
    FreeConsole();

    HANDLE nul = CreateFileA("NUL",
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (nul != INVALID_HANDLE_VALUE) {
        SetStdHandle(STD_OUTPUT_HANDLE, nul);
        SetStdHandle(STD_ERROR_HANDLE, nul);
        SetStdHandle(STD_INPUT_HANDLE, nul);
    }
}
*/

// Anchor the C-side symbol so the linker keeps it.
import "C"
import _ "unsafe"

// noop is referenced from main.go so the import is not dropped.
func noop() { _ = C.sizeof_int }
