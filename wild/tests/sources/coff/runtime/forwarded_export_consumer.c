#include <stdio.h>
#include <windows.h>

__declspec(dllimport) void __stdcall forwarded_sleep(DWORD milliseconds);

int main(void) {
  forwarded_sleep(0);
  puts("wild-pe-forwarded-export");
  return 69;
}
