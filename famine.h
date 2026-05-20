#ifndef _FAMINE_H
# define _FAMINE_H

# include <stddef.h>

#define SIGNATURE "Famine version 1.0 (c)oded by ialgac-beeligul"

int     is_signed(char *adress, size_t lenght);
int     sign_file(char *adress, size_t lenght);
void    scan_targets(void);

#endif
