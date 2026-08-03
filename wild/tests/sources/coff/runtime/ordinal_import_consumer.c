#include <stdio.h>

__declspec(dllimport) int ordinal_export(void);

int main(void) {
  printf("wild-pe-ordinal-import %d\n", ordinal_export());
  return 68;
}
