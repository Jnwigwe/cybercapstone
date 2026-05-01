//By: Gavin Hecke
#include <signal.h>

int kill_process(int pid) {
    // sends the 9 option to force the process to terminate
    if (kill(pid, SIGKILL) == 0) {
        //should add logging here to show what was killed
        //logkill(Process_name, pid)
        return 0;  // Success
    } else {
        return -1;  // Failed
    }
}
