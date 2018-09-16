#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

sig_atomic_t received_signal = 0;

void handle_sigusr1(int signal)
{
    received_signal = (signal == SIGUSR1);
}

int main(int argc, char *argv[], char *envp[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s command...\n", argv[0]);
        return 1;
    }

    // Set up signal handler
    signal(SIGUSR1, handle_sigusr1);

    // Wait for SIGUSR1
    while (!received_signal) usleep(50000);

    // Launch target
	execvpe(argv[1], &argv[1], envp);
}
