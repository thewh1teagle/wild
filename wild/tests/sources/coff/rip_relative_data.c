volatile int writable_value = 19;
volatile const int readonly_value = 28;

int mainCRTStartup(void) { return writable_value + readonly_value; }
