extern volatile int zero_initialized;

int mainCRTStartup(void) {
    zero_initialized += 53;
    return zero_initialized;
}
