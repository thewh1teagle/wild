static int value = 59;
int *volatile absolute_pointer = &value;

int mainCRTStartup(void) { return *absolute_pointer; }
