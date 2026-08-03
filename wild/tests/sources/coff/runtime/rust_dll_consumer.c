#include <stdio.h>

__declspec(dllimport) int rust_exported(int left, int right);

int main(void) {
  int value = rust_exported(19, 20);
  printf("wild-pe-rust-dll %d\n", value);
  return value == 42 ? 67 : 7;
}
