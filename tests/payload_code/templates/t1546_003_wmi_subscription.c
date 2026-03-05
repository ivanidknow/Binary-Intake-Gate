/*
 * T1546.003 — WMI Event Subscription. Persistence via __EventFilter, CommandLineEventConsumer.
 */
#include <windows.h>

static const char *wmi_filter = "__EventFilter";
static const char *wmi_consumer = "CommandLineEventConsumer";

int main(void) {
    (void)wmi_filter;
    (void)wmi_consumer;
    CoInitializeEx(NULL, 0);
    CoUninitialize();
    return 0;
}
