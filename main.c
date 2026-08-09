#include "famine.h"

#include <stdio.h>
#include <sys/file.h>

static int	g_lock_fd = -1;

static int should_run(void)
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "[famine] blocked: root required\n");
        return 0;
    }
    if (access("/tmp/famine.launch", F_OK) != 0)
    {
        fprintf(stderr, "[famine] blocked: /tmp/famine.launch missing\n");
        return 0;
    }
    return 1;
}

static int acquire_lock(void)
{
    g_lock_fd = open("/tmp/famine.run.lock", O_CREAT | O_RDWR, 0600);
    if (g_lock_fd == -1)
    {
        fprintf(stderr, "[famine] lock open failed\n");
        return -1;
    }
    if (flock(g_lock_fd, LOCK_EX | LOCK_NB) == -1)
    {
        close(g_lock_fd);
        g_lock_fd = -1;
        fprintf(stderr, "[famine] blocked: another run is already active\n");
        return 0;
    }
    return 1;
}

static void release_lock(void)
{
    if (g_lock_fd != -1)
    {
        flock(g_lock_fd, LOCK_UN);
        close(g_lock_fd);
        g_lock_fd = -1;
    }
    unlink("/tmp/famine.run.lock");
}

int main(void)
{
    if (!should_run())
        return 0;
    int lock_status = acquire_lock();
    if (lock_status <= 0)
        return 0;
    atexit(release_lock);
    scan_targets();
    return 0;
}
