module flowforge_file_mode_test;
import flowforge::generator;
import flowforge::pcap;
import flowforge::registry;
import flowforge::testutil;
import std::collections::list;
import std::io;

fn char byte_at(char[] bytes, usz offset) => bytes[offset];

fn uint u32_le_at(char[] bytes, usz offset) {
	return (uint)byte_at(bytes, offset)
		| ((uint)byte_at(bytes, offset + 1) << 8)
		| ((uint)byte_at(bytes, offset + 2) << 16)
		| ((uint)byte_at(bytes, offset + 3) << 24);
}

fn bool bytes_equal(char[] a, char[] b) {
	if (a.len != b.len) return false;
	for (usz i = 0; i < a.len; i++) {
		if (a[i] != b[i]) return false;
	}
	return true;
}

fn void test_generator_caps_range_expansion() @test {
	Registry reg = registry::create_default_registry();
	PacketGenerator gen = { .registry = &reg };

	generator::MaybeCount two;
	two.set(2);
	PacketGenerationResult result = gen.prepare(testutil::must_parse(`IP(src="[10.0.0.1-10.0.0.3]")`), two);

	assert(result.ok);
	assert(result.has_packet);
	assert(result.packet.flow_plan.total_flows == 3);
	assert(result.packet.flow_plan.planned_packets == 2);
	assert(result.packet.packet_len == 20);
}

fn void test_generator_produces_per_flow_payloads() @test {
	Registry reg = registry::create_default_registry();
	PacketGenerator gen = { .registry = &reg };

	PacketGenerationResult result = gen.prepare(testutil::must_parse(`IP(src="[10.0.0.1-10.0.0.3]")`));
	assert(result.ok);
	assert(result.has_packet);

	List{String} errors;
	errors.tinit();

	char[]? payload = gen.payload_for_flow(&result.packet, 2, tmem, &errors);
	if (catch payload) unreachable();

	assert(payload.len == 20);
	assert(payload[12] == 10);
	assert(payload[15] == 3);
}

fn void test_generator_applies_flow_into_prefilled_buffer_repeatedly() @test {
	Registry reg = registry::create_default_registry();
	PacketGenerator gen = { .registry = &reg };

	PacketGenerationResult result = gen.prepare(
		testutil::must_parse(`IP(src="[10.0.0.1-10.0.0.2]",dst="10.0.1.1")/UDP(sport="[10000-10001]",dport=53)`));
	assert(result.ok);
	assert(result.has_packet);
	assert(result.packet.flow_plan.total_flows == 4);

	List{String} errors;
	errors.tinit();

	char[]? first_expected = gen.payload_for_flow(&result.packet, 0, tmem, &errors);
	if (catch first_expected) unreachable();
	assert(errors.len() == 0);
	char[]? last_expected = gen.payload_for_flow(&result.packet, 3, tmem, &errors);
	if (catch last_expected) unreachable();
	assert(errors.len() == 0);

	char[] reusable = alloc::new_array(tmem, char, (sz)result.packet.packet_len);
	mem::copy(reusable.ptr, result.packet.base_payload.ptr, (sz)result.packet.packet_len);

	assert(gen.apply_flow(&result.packet, 0, reusable, &errors));
	assert(errors.len() == 0);
	assert(bytes_equal(reusable, first_expected));

	assert(gen.apply_flow(&result.packet, 3, reusable, &errors));
	assert(errors.len() == 0);
	assert(bytes_equal(reusable, last_expected));

	assert(gen.apply_flow(&result.packet, 0, reusable, &errors));
	assert(errors.len() == 0);
	assert(bytes_equal(reusable, first_expected));
}

fn void test_pcap_writer_writes_classic_ethernet_pcap() @test {
	ByteWriter output;
	output.tinit();
	PcapWriter writer = { .output = &output };

	char[14] payload = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
	};

	assert(writer.write_header().ok);
	assert(writer.write_packet(payload[..]).ok);

	char[] bytes = output.array_view();
	assert(bytes.len == 24 + 16 + 14);
	assert(u32_le_at(bytes, 0) == 0xa1b2c3d4);
	assert(u32_le_at(bytes, 16) == 65535);
	assert(u32_le_at(bytes, 20) == 1);
	assert(u32_le_at(bytes, 32) == 14);
	assert(u32_le_at(bytes, 36) == 14);
	assert(byte_at(bytes, 40) == 0xff);
	assert(byte_at(bytes, 45) == 0xff);
	assert(byte_at(bytes, 52) == 0x08);
	assert(byte_at(bytes, 53) == 0x00);
}

fn void test_pcap_writer_requires_header() @test {
	ByteWriter output;
	output.tinit();
	PcapWriter writer = { .output = &output };

	char[1] payload = { 0 };
	PcapWriteResult result = writer.write_packet(payload[..]);

	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "pcap header must be written before packet records");
}
