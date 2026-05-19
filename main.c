#include "famine.h"
#include <stdlib.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>

int static  check_if_elf(Elf64_Ehdr *elf)
{
    if (elf->e_ident[EI_MAG0] != ELFMAG0 ||
        elf->e_ident[EI_MAG1] != ELFMAG1 ||
        elf->e_ident[EI_MAG2] != ELFMAG2 ||
        elf->e_ident[EI_MAG3] != ELFMAG3)
        return 0;
    if (elf->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;
    return 1;
}

int static  find_note_section(Elf64_Shdr *shdr, size_t shnum, Elf64_Shdr **note_shdr)
{
    for (size_t i = 0; i < shnum; i++)
    {
        if (shdr[i].sh_type == SHT_NOTE)
        {
            *note_shdr = &shdr[i];
            return 1;
        }
    }
    return 0;
}


int     is_signed(char *adress, size_t lenght)
{
    size_t lenght_of_string = strlen(SIGNATURE);
    Elf64_Ehdr *elfh = (Elf64_Ehdr *)adress;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(adress + elfh->e_shoff);
    Elf64_Shdr *note_shdr = NULL;
    Elf64_Off note_offset = 0;

    if (lenght == 0)
        return 0;
    if (check_if_elf(elfh) == 0)
        return 0;
    if (find_note_section(shdr, elfh->e_shnum, &note_shdr) == 0)
        return 0;
    note_offset = note_shdr->sh_offset;
    if (strncmp(adress + note_offset, SIGNATURE, lenght_of_string) != 0)
        return 0;
        
    return 1;
}

int sign_file(char *adress, size_t lenght)
{
    size_t lenght_of_string = strlen(SIGNATURE);

    if (lenght == 0)
        return 0;
    if (check_if_elf((Elf64_Ehdr *)adress) == 0)
        return 0;

    adress += lenght - lenght_of_string;
    memcpy(adress, SIGNATURE, lenght_of_string);
    return 1;
}

int main()
{
    


    return 0;
}