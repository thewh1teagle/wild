#include <windows.h>

__declspec(thread) static int tls_value = 71;
__declspec(thread) static int tls_zero;
static volatile LONG callback_count;

static void NTAPI tls_callback(PVOID module, DWORD reason, PVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH) {
        InterlockedIncrement(&callback_count);
    }
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK tls_callback_entry = tls_callback;

static DWORD WINAPI thread_main(LPVOID context) {
    (void)context;
    if (tls_value != 71 || tls_zero != 0) {
        return 1;
    }
    tls_value = 72;
    tls_zero = 74;
    return tls_value == 72 && tls_zero == 74 ? 0 : 2;
}

int main(void) {
    if (tls_value != 71 || tls_zero != 0 || callback_count < 1) {
        return 1;
    }
    tls_value = 73;
    tls_zero = 75;

    HANDLE thread = CreateThread(NULL, 0, thread_main, NULL, 0, NULL);
    if (thread == NULL) {
        return 2;
    }
    if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
        CloseHandle(thread);
        return 3;
    }
    DWORD thread_status = 0;
    if (!GetExitCodeThread(thread, &thread_status)) {
        CloseHandle(thread);
        return 4;
    }
    CloseHandle(thread);

    return thread_status == 0 && tls_value == 73 && tls_zero == 75 && callback_count >= 2 ? 65 : 5;
}
