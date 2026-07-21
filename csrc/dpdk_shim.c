#include "dpdk_shim.h"

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mempool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

/* --- mbuf layout guard --------------------------------------------------- */

void ff_mbuf_layout(size_t *out) {
	if (out == NULL) {
		return;
	}
	out[0] = offsetof(struct rte_mbuf, buf_addr);
	out[1] = offsetof(struct rte_mbuf, data_off);
	out[2] = offsetof(struct rte_mbuf, ol_flags);
	out[3] = offsetof(struct rte_mbuf, pkt_len);
	out[4] = offsetof(struct rte_mbuf, data_len);
	out[5] = offsetof(struct rte_mbuf, buf_len);
	out[6] = offsetof(struct rte_mbuf, tx_offload);
	out[7] = sizeof(struct rte_mbuf);
}

/* --- inline / thread-local DPDK operations ------------------------------- */

int ff_rte_errno(void) {
	return rte_errno;
}

unsigned ff_lcore_id(void) {
	return rte_lcore_id();
}

int ff_pktmbuf_alloc_bulk(struct rte_mempool *pool, struct rte_mbuf **mbufs, unsigned count) {
	return rte_pktmbuf_alloc_bulk(pool, mbufs, count);
}

int ff_pktmbuf_raw_alloc_bulk(struct rte_mempool *pool, struct rte_mbuf **mbufs, unsigned count) {
	return rte_mempool_get_bulk(pool, (void**)mbufs, count);
}

void ff_pktmbuf_free(struct rte_mbuf *mbuf) {
	rte_pktmbuf_free(mbuf);
}

void ff_pktmbuf_free_bulk(struct rte_mbuf **mbufs, unsigned count) {
	rte_pktmbuf_free_bulk(mbufs, count);
}

uint16_t ff_eth_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
	return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}

uint16_t ff_eth_tx_prepare(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts) {
	return rte_eth_tx_prepare(port_id, queue_id, tx_pkts, nb_pkts);
}

uint16_t ff_eth_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, uint16_t nb_pkts) {
	return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

int ff_eth_dev_configure(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q) {
	struct rte_eth_conf port_conf;
	memset(&port_conf, 0, sizeof(port_conf));
	return rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &port_conf);
}

int ff_eth_stats_get(uint16_t port_id, struct ff_eth_stats *out) {
	struct rte_eth_stats stats;
	memset(&stats, 0, sizeof(stats));
	int rc = rte_eth_stats_get(port_id, &stats);
	if (rc == 0 && out != NULL) {
		out->ipackets = stats.ipackets;
		out->opackets = stats.opackets;
		out->ibytes = stats.ibytes;
		out->obytes = stats.obytes;
		out->imissed = stats.imissed;
		out->ierrors = stats.ierrors;
		out->oerrors = stats.oerrors;
		out->rx_nombuf = stats.rx_nombuf;
	}
	return rc;
}

/* --- lcore enumeration --------------------------------------------------- */

unsigned ff_worker_lcores(uint32_t *out, unsigned max) {
	unsigned count = 0;
	unsigned lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (out != NULL && count < max) {
			out[count] = lcore_id;
		}
		++count;
	}
	return count;
}

/* --- test helpers -------------------------------------------------------- */

struct rte_mbuf *ff_test_alloc_mbuf(void) {
	struct rte_mbuf *mbuf = (struct rte_mbuf *)calloc(1, sizeof(struct rte_mbuf));
	return mbuf;
}

void ff_test_free_mbuf(struct rte_mbuf *mbuf) {
	free(mbuf);
}

/* --- TAP preflight ------------------------------------------------------- */

int ff_check_tap_permission(const char *iface, char *err, size_t err_len) {
#ifdef __linux__
	int tun_fd = open("/dev/net/tun", O_RDWR);
	if (tun_fd < 0) {
		if (err != NULL && err_len > 0) {
			snprintf(err, err_len, "failed to open /dev/net/tun for TAP preflight: %s", strerror(errno));
		}
		return -1;
	}

	struct ifreq request;
	memset(&request, 0, sizeof(request));
	request.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(request.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(tun_fd, TUNSETIFF, &request) < 0) {
		if (err != NULL && err_len > 0) {
			snprintf(err, err_len, "failed to create TAP interface '%s' during preflight: %s", iface, strerror(errno));
		}
		close(tun_fd);
		return -1;
	}

	close(tun_fd);
	return 0;
#else
	(void)iface;
	(void)err;
	(void)err_len;
	return 0;
#endif
}
