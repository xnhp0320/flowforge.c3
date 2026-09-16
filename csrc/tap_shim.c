#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include <unistd.h>
#ifdef __linux__
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#endif

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "TAP stop flag must be signal-safe");
static atomic_int stopped;
static struct sigaction old_int, old_term;
static void stop_handler(int sig) { (void)sig; atomic_store_explicit(&stopped, 1, memory_order_relaxed); }
void ff_tap_signals_start(void) {
	struct sigaction action = {0};
	action.sa_handler = stop_handler;
	sigemptyset(&action.sa_mask);
	atomic_store(&stopped, 0);
	sigaction(SIGINT, &action, &old_int);
	sigaction(SIGTERM, &action, &old_term);
}
void ff_tap_signals_end(void) {
	sigaction(SIGINT, &old_int, NULL);
	sigaction(SIGTERM, &old_term, NULL);
}
int ff_tap_stopped(void) { return atomic_load_explicit(&stopped, memory_order_relaxed); }
void ff_tap_stop(void) { atomic_store_explicit(&stopped, 1, memory_order_relaxed); }
long long ff_tap_seconds(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}
int ff_tap_open(const char *name, int multi, char *error, size_t size) {
#ifdef __linux__
	int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) goto fail;
	struct ifreq req = {0};
	snprintf(req.ifr_name, IFNAMSIZ, "%s", name);
	req.ifr_flags = IFF_TAP | IFF_NO_PI | (multi ? IFF_MULTI_QUEUE : 0);
	if (ioctl(fd, TUNSETIFF, &req) < 0) {
		// A persistent interface may have been provisioned with multi_queue
		// even when this run uses one worker. Preserve that interface mode.
		if (multi || errno != EINVAL) goto close_fail;
		req.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;
		if (ioctl(fd, TUNSETIFF, &req) < 0) goto close_fail;
	}
	int ctl = socket(AF_INET, SOCK_DGRAM, 0);
	if (ctl < 0) goto close_fail;
	if (ioctl(ctl, SIOCGIFFLAGS, &req) < 0) { close(ctl); goto close_fail; }
	req.ifr_flags |= IFF_UP;
	int rc = ioctl(ctl, SIOCSIFFLAGS, &req);
	int saved = errno;
	close(ctl);
	errno = saved;
	if (rc < 0) goto close_fail;
	return fd;
close_fail: {
	int saved = errno;
	close(fd);
	errno = saved;
}
fail:
	snprintf(error, size, "TAP '%s': %s (requires /dev/net/tun and CAP_NET_ADMIN)", name, strerror(errno));
#else
	(void)name; (void)multi;
	snprintf(error, size, "tap backend is supported only on Linux; use the Lima VM on macOS");
#endif
	return -1;
}
int ff_tap_send(int fd, const char *data, size_t size) {
#ifdef __linux__
	for (int attempt = 0; attempt < 20 && !ff_tap_stopped(); attempt++) {
		ssize_t n = write(fd, data, size);
		if (n >= 0) return n == (ssize_t)size ? 1 : -EIO;
		if (errno == EINTR) { attempt--; continue; }
		if (errno != EAGAIN && errno != EWOULDBLOCK) return -errno;
		struct pollfd pfd = { .fd = fd, .events = POLLOUT };
		poll(&pfd, 1, 50);
	}
	return ff_tap_stopped() ? 0 : -EAGAIN;
#else
	(void)fd; (void)data; (void)size; return -1;
#endif
}
int ff_tap_receive(int fd, char *data, size_t size) {
	ssize_t n;
	do { n = read(fd, data, size); } while (n < 0 && errno == EINTR && !ff_tap_stopped());
	if (n >= 0) return (int)n;
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
	return -errno;
}
void ff_tap_close(int fd) { close(fd); }
void ff_tap_idle(void) {
	struct timespec delay = { .tv_nsec = 1000000 };
	nanosleep(&delay, NULL);
}
