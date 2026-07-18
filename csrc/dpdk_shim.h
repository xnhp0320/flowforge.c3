/*
 * C shim exposing the DPDK helpers the FlowForge C3 runtime needs.
 *
 * DPDK exposes a large amount of functionality through macros, thread-local
 * variables and `static inline` functions that have no exported symbol and so
 * cannot be bound directly from C3. This shim wraps exactly those pieces (plus
 * a couple of Linux TAP preflight helpers) behind plain, C-ABI functions.
 */
#ifndef FLOWFORGE_DPDK_SHIM_H
#define FLOWFORGE_DPDK_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rte_mbuf;
struct rte_mempool;

/* Mirrors serializer::OffloadLayer3. */
enum ff_offload_layer3 {
	FF_OFFLOAD_L3_NONE = 0,
	FF_OFFLOAD_L3_IPV4 = 1,
	FF_OFFLOAD_L3_IPV6 = 2,
};

/* Aggregated ethdev counters we read back (subset of rte_eth_stats). */
struct ff_eth_stats {
	uint64_t ipackets;
	uint64_t opackets;
	uint64_t ibytes;
	uint64_t obytes;
	uint64_t imissed;
	uint64_t ierrors;
	uint64_t oerrors;
	uint64_t rx_nombuf;
};

/* --- constants (exposed as functions to avoid macro-linkage issues) ------- */
uint64_t ff_flag_tx_ipv4(void);
uint64_t ff_flag_tx_ipv6(void);
uint64_t ff_flag_tx_ip_cksum(void);
uint64_t ff_flag_tx_tcp_cksum(void);
uint64_t ff_flag_tx_udp_cksum(void);
uint64_t ff_flag_tx_l4_mask(void);
uint32_t ff_mbuf_default_buf_size(void);
unsigned ff_lcore_wait_state(void);

/* --- mbuf layout guard ---------------------------------------------------
 * The C3 side mirrors struct rte_mbuf directly for field access; this reports
 * the real offsets/size so a unit test can assert the mirror stays in sync.
 * Order: [0]=buf_addr [1]=data_off [2]=ol_flags [3]=pkt_len
 *        [4]=data_len [5]=buf_len  [6]=tx_offload [7]=sizeof(struct rte_mbuf) */
void ff_mbuf_layout(size_t *out);

/* --- inline / thread-local DPDK operations ------------------------------- */
int ff_rte_errno(void);
unsigned ff_lcore_id(void);
int ff_pktmbuf_alloc_bulk(struct rte_mempool *pool, struct rte_mbuf **mbufs, unsigned count);
void ff_pktmbuf_free(struct rte_mbuf *mbuf);
void ff_pktmbuf_free_bulk(struct rte_mbuf **mbufs, unsigned count);
uint16_t ff_eth_tx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t ff_eth_tx_prepare(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t ff_eth_rx_burst(uint16_t port_id, uint16_t queue_id, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

/* rte_eth_dev_configure with a zero-initialised rte_eth_conf. */
int ff_eth_dev_configure(uint16_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q);
int ff_eth_stats_get(uint16_t port_id, struct ff_eth_stats *out);

/* Applies a checksum offload request to an mbuf (mirrors
 * apply_dpdk_offload_request in the C++ reference). */
void ff_apply_dpdk_offload(struct rte_mbuf *mbuf,
	int layer3,
	int ipv4_checksum,
	int tcp_checksum,
	int udp_checksum,
	uint64_t l2_len,
	uint64_t l3_len,
	uint64_t l4_len);

/* Enumerates the worker (non-main) lcores into `out` (capacity `max`);
 * returns the number of worker lcores available. */
unsigned ff_worker_lcores(uint32_t *out, unsigned max);

/* Allocates / frees a standalone zeroed rte_mbuf for unit tests that must not
 * initialise the EAL. */
struct rte_mbuf *ff_test_alloc_mbuf(void);
void ff_test_free_mbuf(struct rte_mbuf *mbuf);

/* TAP preflight: open /dev/net/tun and TUNSETIFF on `iface`. Returns 0 on
 * success, otherwise writes a message into `err` and returns -1. */
int ff_check_tap_permission(const char *iface, char *err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif /* FLOWFORGE_DPDK_SHIM_H */
