#include <stdio.h>

__declspec(dllimport) int delay_add(int left, int right);

int main(void) {
  printf("wild-pe-delay %d\n", delay_add(19, 23));
  return 70;
}
