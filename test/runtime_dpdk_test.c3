module flowforge_runtime_dpdk_test;
import flowforge::runtime;
import flowforge::dpdk;
import flowforge::serializer;

ushort recorded_rss_port;
uint recorded_rss_mask_bits;

struct RecordedDriver (dpdk::DriverOps) {
	uint mask_bits;
}

fn int RecordedDriver.set_rss(&self, ushort port_id) @dynamic {
	recorded_rss_port = port_id;
	recorded_rss_mask_bits = self.mask_bits;
	return -17;
}

fn void test_xsl_rss_queue_count_conversion() @test {
	uint mask_bits;
	assert(dpdk::rss_lb_mask_bits(1, &mask_bits) && mask_bits == 0);
	assert(dpdk::rss_lb_mask_bits(2, &mask_bits) && mask_bits == 1);
	assert(dpdk::rss_lb_mask_bits(4, &mask_bits) && mask_bits == 2);
	assert(dpdk::rss_lb_mask_bits(8, &mask_bits) && mask_bits == 3);
	assert(!dpdk::rss_lb_mask_bits(0, &mask_bits));
	assert(!dpdk::rss_lb_mask_bits(3, &mask_bits));
	assert(!dpdk::rss_lb_mask_bits(6, &mask_bits));
}

fn void test_xsl_driver_interface_dispatches_stored_operation() @test {
	RecordedDriver recorded_driver = { .mask_bits = 3 };
	dpdk::DriverOps driver_ops = &recorded_driver;
	int rc = driver_ops.set_rss(7);

	assert(rc == -17);
	assert(recorded_rss_port == 7);
	assert(recorded_rss_mask_bits == 3);
}

fn void test_xsl_driver_name_selection_is_exact() @test {
	assert(dpdk::is_xsl_driver("net_xsl"));
	assert(!dpdk::is_xsl_driver("net_tap"));
	assert(!dpdk::is_xsl_driver("xsl"));
}

fn void test_unstarted_live_port_run_fails_with_warning_only() @test {
	Result result;
	result.tinit();
	result.warnings.push("invalid XSL RX queue count");
	runtime::finish_live_port_run(&result, false);
	assert(!result.ok);
	assert(result.errors.len() == 0);
}

<* Mirrors RuntimeTest.AppliesDpdkOffloadRequestToMbufMetadata. Exercises the
   real C3 offload wrapper + C shim against a standalone (EAL-free) mbuf. *>
fn void test_applies_dpdk_offload_request_to_mbuf_metadata() @test {
	Mbuf* mbuf = dpdk::ff_test_alloc_mbuf();
	assert(mbuf != null);
	defer dpdk::ff_test_free_mbuf(mbuf);

	PacketOffloadRequest request;
	request.layer3 = OffloadLayer3.IPV4;
	request.ipv4_checksum = true;
	request.udp_checksum = true;
	request.l2_len = 14;
	request.l3_len = 20;
	request.l4_len = 8;

	runtime::apply_dpdk_offload(mbuf, request);

	ulong ol_flags = mbuf.ol_flags;
	assert((ol_flags & dpdk::TX_IPV4) != 0);
	assert((ol_flags & dpdk::TX_IP_CKSUM) != 0);
	assert((ol_flags & dpdk::TX_L4_MASK) == dpdk::TX_UDP_CKSUM);
	assert(mbuf.tx_offload.l2_len == 14);
	assert(mbuf.tx_offload.l3_len == 20);
	assert(mbuf.tx_offload.l4_len == 8);
}

fn void test_tcp_offload_sets_tcp_checksum_flag() @test {
	Mbuf* mbuf = dpdk::ff_test_alloc_mbuf();
	assert(mbuf != null);
	defer dpdk::ff_test_free_mbuf(mbuf);

	PacketOffloadRequest request;
	request.layer3 = OffloadLayer3.IPV6;
	request.tcp_checksum = true;
	request.l2_len = 14;
	request.l3_len = 40;
	request.l4_len = 20;

	runtime::apply_dpdk_offload(mbuf, request);

	ulong ol_flags = mbuf.ol_flags;
	assert((ol_flags & dpdk::TX_IPV6) != 0);
	assert((ol_flags & dpdk::TX_IP_CKSUM) == 0);
	assert((ol_flags & dpdk::TX_L4_MASK) == dpdk::TX_TCP_CKSUM);
	assert(mbuf.tx_offload.l3_len == 40);
	assert(mbuf.tx_offload.l4_len == 20);
}

fn void test_vxlan_offload_sets_tunnel_and_outer_metadata() @test {
	Mbuf* mbuf = dpdk::ff_test_alloc_mbuf();
	assert(mbuf != null);
	defer dpdk::ff_test_free_mbuf(mbuf);

	PacketOffloadRequest request;
	request.layer3 = OffloadLayer3.IPV4;
	request.tunnel_vxlan = true;
	request.outer_ipv4_checksum = true;
	request.ipv4_checksum = true;
	request.tcp_checksum = true;
	request.outer_l2_len = 14;
	request.outer_l3_len = 20;
	request.l2_len = 30;
	request.l3_len = 20;
	request.l4_len = 20;

	runtime::apply_dpdk_offload(mbuf, request);

	ulong ol_flags = mbuf.ol_flags;
	assert((ol_flags & dpdk::TX_TUNNEL_MASK) == dpdk::TX_TUNNEL_VXLAN);
	assert((ol_flags & dpdk::TX_OUTER_IPV4) != 0);
	assert((ol_flags & dpdk::TX_OUTER_IP_CKSUM) != 0);
	assert((ol_flags & dpdk::TX_IPV4) != 0);
	assert((ol_flags & dpdk::TX_IP_CKSUM) != 0);
	assert((ol_flags & dpdk::TX_L4_MASK) == dpdk::TX_TCP_CKSUM);
	assert(mbuf.tx_offload.outer_l2_len == 14);
	assert(mbuf.tx_offload.outer_l3_len == 20);
	assert(mbuf.tx_offload.l2_len == 30);
	assert(mbuf.tx_offload.l3_len == 20);
	assert(mbuf.tx_offload.l4_len == 20);
}

fn void test_offload_request_without_checksums_is_noop() @test {
	Mbuf* mbuf = dpdk::ff_test_alloc_mbuf();
	assert(mbuf != null);
	defer dpdk::ff_test_free_mbuf(mbuf);

	PacketOffloadRequest request;
	request.layer3 = OffloadLayer3.NONE;
	request.l2_len = 14;
	request.l3_len = 20;
	request.l4_len = 8;

	runtime::apply_dpdk_offload(mbuf, request);

	assert(mbuf.ol_flags == 0);
	assert(mbuf.tx_offload.l2_len == 0);
	assert(mbuf.tx_offload.l3_len == 0);
	assert(mbuf.tx_offload.l4_len == 0);
}

<* Guards the C3 `Mbuf` mirror against the real DPDK layout. If DPDK's build
   config or version ever moves a field we access, this fails loudly instead of
   letting the mismatched offset corrupt memory at runtime. *>
fn void test_mbuf_layout_matches_dpdk() @test {
	usz[dpdk::FF_MBUF_LAYOUT_FIELDS] real;
	dpdk::ff_mbuf_layout(&real[0]);

	assert($reflect(Mbuf.buf_addr).offset == real[0]);
	assert($reflect(Mbuf.data_off).offset == real[1]);
	assert($reflect(Mbuf.ol_flags).offset == real[2]);
	assert($reflect(Mbuf.pkt_len).offset == real[3]);
	assert($reflect(Mbuf.data_len).offset == real[4]);
	assert($reflect(Mbuf.buf_len).offset == real[5]);
	assert($reflect(Mbuf.tx_offload).offset == real[6]);
	assert(Mbuf::size == real[7]);
}
