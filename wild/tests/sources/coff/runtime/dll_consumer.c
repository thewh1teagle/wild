#include <stdio.h>

__declspec(dllimport) extern int exported_value;
__declspec(dllimport) int add_exported(int left, int right);

int main(void) {
  printf("wild-pe-dll %d %d\n", add_exported(19, 23), exported_value);
  return 63;
}
