module flowforge::serializer @feat(DPDK);
import flowforge::dpdk;

fn ulong range_random_u64() @private {
	return dpdk::rte_rand();
}
