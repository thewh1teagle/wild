#include <stdio.h>

__declspec(dllimport) int cpp_exported(void);

int main(void) {
  int value = cpp_exported();
  printf("wild-pe-cpp-dll %d\n", value);
  return value == 42 ? 66 : 6;
}
