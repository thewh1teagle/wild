__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned long exit_code);

void mainCRTStartup(void) { ExitProcess(37); }
