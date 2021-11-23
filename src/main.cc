#include <iostream>
#include <signal.h>
#include <execinfo.h>
#include "server.h"
#include "config.h"

using namespace std;

void crash_handler(int sig) {
    void *trace[256];
    int size = backtrace(trace, 256);
    int fd = open("rdpproxy.crash", O_WRONLY | O_CREAT);
    backtrace_symbols_fd(trace, size, fd);
    exit(1);
}

Configuration configuration;

int main(int argc, char **argv) {
    signal(SIGABRT, crash_handler);
    signal(SIGSEGV, crash_handler);
    signal(SIGPIPE, SIG_IGN);
    if (argc != 2) {
        cout << "Usage: rdpproxy <config.json>\n";
        return 0;
    }
    if (!load_configuration(argv[1], configuration)) {
        return -1;
    } 
    RDPProxyServer server;
    server.run();
    return 0;
}