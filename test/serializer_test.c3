module flowforge_serializer_test;
import flowforge::constructor;
import flowforge::registry;
import flowforge::serializer;
import flowforge::testutil;

fn BuildResult build_default(String input) {
	Registry reg = registry::create_default_registry();
	return constructor::build(&reg, testutil::must_parse(input));
}

fn BuildResult build_with(String input, Registry* reg) {
	return constructor::build(reg, testutil::must_parse(input));
}

fn SerializeResult serialize_into(PacketConstructor packet, char[] buffer) {
	Registry reg = registry::create_default_registry();
	return serializer::serialize_packet(packet, &reg, buffer);
}

fn PayloadFieldModifier* find_modifier(SerializeResult result, String protocol, String field) {
	foreach (&m : result.modifiers) {
		if (m.protocol == protocol && m.field == field) return m;
	}
	return null;
}

fn char byte_at(char[] bytes, usz offset) => bytes[offset];

fn ushort u16_at(char[] bytes, usz offset) {
	return (ushort)(((ushort)byte_at(bytes, offset) << 8) | (ushort)byte_at(bytes, offset + 1));
}

fn void test_serializes_ether_ip_udp_scalars() @test {
	BuildResult built = build_default(
		`Ether(dst="ff:ff:ff:ff:ff:ff",src="00:11:22:33:44:55",type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=53,dport=54)`);
	assert(built.ok);
	char[64] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(result.packet_len == 42);
	assert(byte_at(buf[..], 0) == 0xff);
	assert(byte_at(buf[..], 5) == 0xff);
	assert(byte_at(buf[..], 6) == 0x00);
	assert(byte_at(buf[..], 7) == 0x11);
	assert(byte_at(buf[..], 11) == 0x55);
	assert(u16_at(buf[..], 12) == 0x0800);
	assert(byte_at(buf[..], 14) == 0x45);
	assert(byte_at(buf[..], 22) == 64);
	assert(byte_at(buf[..], 23) == 17);
	assert(byte_at(buf[..], 26) == 192);
	assert(byte_at(buf[..], 29) == 1);
	assert(byte_at(buf[..], 33) == 2);
	assert(u16_at(buf[..], 34) == 53);
	assert(u16_at(buf[..], 36) == 54);
	assert(u16_at(buf[..], 38) == 0);
}

fn void test_serializes_vlan_cross_byte_fields() @test {
	BuildResult built = build_default("VLAN(prio=7,dei=1,vlan=4095,type=2048)");
	assert(built.ok);
	char[4] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(result.packet_len == 4);
	assert(byte_at(buf[..], 0) == 0xff);
	assert(byte_at(buf[..], 1) == 0xff);
	assert(u16_at(buf[..], 2) == 0x0800);
}

fn void test_rejects_small_output_buffer() @test {
	BuildResult built = build_default("Ether()/IP()/UDP()");
	assert(built.ok);
	char[8] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("packet requires 42 bytes"));
}

fn void test_payload_length_extends_serialized_packet() @test {
	BuildResult built = build_default("Ether()/Payload(length=32)");
	assert(built.ok);
	char[64] buf;
	for (usz i = 0; i < buf.len; i++) buf[i] = (char)0xff;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(result.packet_len == 46);
	assert(byte_at(buf[..], 14) == 0);
	assert(byte_at(buf[..], 45) == 0);
	assert(byte_at(buf[..], 46) == 0xff);
}

fn void test_payload_total_length_extends_serialized_packet() @test {
	BuildResult built = build_default("Ether()/IP()/Payload(total_length=100)");
	assert(built.ok);
	char[128] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(result.packet_len == 100);
}

fn void test_serializes_ipv4_options_and_advances_next_header() @test {
	BuildResult built = build_default("IP(options=IPOption_NOP()/IPOption_EOL())/TCP()");
	assert(built.ok);
	char[64] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(result.packet_len == 44);
	assert(byte_at(buf[..], 0) == 0x46);
	assert(byte_at(buf[..], 20) == 1);
	assert(byte_at(buf[..], 21) == 0);
	assert(byte_at(buf[..], 22) == 0);
	assert(byte_at(buf[..], 23) == 0);
	assert(byte_at(buf[..], 24 + 12) == 0x50);
}

fn void test_serializes_tcp_options_and_pads_header() @test {
	BuildResult built = build_default("IP()/TCP(options=TCPOption_MSS(value=1460))");
	assert(built.ok);
	char[64] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(result.packet_len == 44);
	assert(byte_at(buf[..], 20 + 12) == 0x60);
	assert(byte_at(buf[..], 40) == 2);
	assert(byte_at(buf[..], 41) == 4);
	assert(u16_at(buf[..], 42) == 1460);
}

fn void test_tcp_option_header_length_feeds_hardware_offload() @test {
	BuildResult built = build_default("IP()/TCP(options=TCPOption_MSS(value=1460))/Payload(length=4)");
	assert(built.ok);
	char[64] buf;
	SerializeResult serialize = serialize_into(built.packet, buf[..]);
	assert(serialize.ok);

	Registry reg = registry::create_default_registry();
	FixupOptions options;
	options.tcp_checksum = FixupMode.HARDWARE_OFFLOAD;
	FixupResult fixup = serializer::fixup_packet(built.packet, &reg, buf[..], serialize.packet_len, options);

	assert(fixup.ok);
	assert(fixup.offload.tcp_checksum);
	assert(fixup.offload.l3_len == 20);
	assert(fixup.offload.l4_len == 24);
}

fn void test_serializes_first_range_value_into_base_payload() @test {
	BuildResult built = build_default(`IP(src="[10.0.0.2-10.0.0.4]",dst="10.0.1.1-10.0.1.2")`);
	assert(built.ok);
	char[20] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(byte_at(buf[..], 12) == 10);
	assert(byte_at(buf[..], 15) == 2);
	assert(byte_at(buf[..], 16) == 10);
	assert(byte_at(buf[..], 19) == 1);
	PayloadFieldModifier* src_modifier = find_modifier(result, "IP", "src");
	assert(src_modifier != null);
	assert(src_modifier.value_count == 3);
	PayloadFieldModifier* dst_modifier = find_modifier(result, "IP", "dst");
	assert(dst_modifier != null);
	assert(dst_modifier.value_count == 2);
}

fn void test_serializes_first_ipv6_range_value_into_base_payload() @test {
	BuildResult built = build_default(`IPv6(src="[2001:db8::2-2001:db8::4]")`);
	assert(built.ok);
	char[40] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);

	assert(result.ok);
	assert(byte_at(buf[..], 8) == 0x20);
	assert(byte_at(buf[..], 9) == 0x01);
	assert(byte_at(buf[..], 22) == 0x00);
	assert(byte_at(buf[..], 23) == 0x02);
	PayloadFieldModifier* modifier = find_modifier(result, "IPv6", "src");
	assert(modifier != null);
	assert(modifier.value_count == 3);
}

fn void test_serializes_first_bit_range_value_into_base_payload() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("MyHdr", { registry::fld("field", "b16_ranges") });
	BuildResult built = build_with(`MyHdr(field="[100-102]")`, &reg);
	assert(built.ok);
	char[2] buf;
	SerializeResult result = serializer::serialize_packet(built.packet, &reg, buf[..]);

	assert(result.ok);
	assert(u16_at(buf[..], 0) == 100);
	PayloadFieldModifier* modifier = find_modifier(result, "MyHdr", "field");
	assert(modifier != null);
	assert(modifier.value_count == 3);
}

fn void test_modifier_applies_list_index_to_payload() @test {
	BuildResult built = build_default(`IP(src="[10.0.0.1-10.0.0.2, 10.0.1.1-10.0.1.2]")`);
	assert(built.ok);
	char[20] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);
	assert(result.ok);
	PayloadFieldModifier* modifier = find_modifier(result, "IP", "src");
	assert(modifier != null);

	String error = "";
	assert(modifier.apply(buf[..], 2, &error));
	assert(byte_at(buf[..], 12) == 10);
	assert(byte_at(buf[..], 13) == 0);
	assert(byte_at(buf[..], 14) == 1);
	assert(byte_at(buf[..], 15) == 1);
}

fn void test_modifier_rejects_out_of_range_index() @test {
	BuildResult built = build_default(`IP(src="[10.0.0.1-10.0.0.2]")`);
	assert(built.ok);
	char[20] buf;
	SerializeResult result = serialize_into(built.packet, buf[..]);
	assert(result.ok);
	PayloadFieldModifier* modifier = find_modifier(result, "IP", "src");
	assert(modifier != null);

	String error = "";
	assert(!modifier.apply(buf[..], 2, &error));
	assert(error.contains("out of range"));
}

fn void test_modified_payload_can_be_fixed_up_again() @test {
	BuildResult built = build_default(
		`Ether(type=2048)/IP(src="[192.168.0.1-192.168.0.3]",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=53,dport=54)`);
	assert(built.ok);
	char[64] buf;
	Registry reg = registry::create_default_registry();

	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);
	PayloadFieldModifier* modifier = find_modifier(serialize, "IP", "src");
	assert(modifier != null);

	String error = "";
	assert(modifier.apply(buf[..], 2, &error));
	FixupResult fixup = serializer::fixup_packet(built.packet, &reg, buf[..], serialize.packet_len);

	assert(fixup.ok);
	assert(byte_at(buf[..], 26) == 192);
	assert(byte_at(buf[..], 29) == 3);
	assert(serializer::fold_checksum(serializer::checksum_sum(buf[14:20])) == 0xffff);
	uint pseudo = serializer::ipv4_pseudo_sum(buf[..], 14, (char)17, (ushort)8);
	assert(serializer::fold_checksum(pseudo + serializer::checksum_sum(buf[34:8])) == 0xffff);
}

fn void test_planned_software_fixup_can_be_reused_after_range_mutation() @test {
	BuildResult built = build_default(
		`Ether(type=2048)/IP(src="[192.168.0.1-192.168.0.3]",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=53,dport=54)`);
	assert(built.ok);
	char[64] buf;
	Registry reg = registry::create_default_registry();

	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);
	FixupPlanResult plan = serializer::plan_packet_fixups(built.packet, &reg, buf[..], serialize.packet_len);
	assert(plan.ok);
	PayloadFieldModifier* modifier = find_modifier(serialize, "IP", "src");
	assert(modifier != null);

	String error = "";
	assert(modifier.apply(buf[..], 2, &error));
	FixupResult fixup = serializer::apply_fixup_plan(buf[..], plan.plan);

	assert(fixup.ok);
	assert(byte_at(buf[..], 29) == 3);
	assert(serializer::fold_checksum(serializer::checksum_sum(buf[14:20])) == 0xffff);
	uint pseudo = serializer::ipv4_pseudo_sum(buf[..], 14, (char)17, (ushort)8);
	assert(serializer::fold_checksum(pseudo + serializer::checksum_sum(buf[34:8])) == 0xffff);
}

fn void test_planned_hardware_fixup_reuses_offload_metadata_and_refreshes_pseudo_seed() @test {
	BuildResult built = build_default(
		`Ether(type=2048)/IP(src="[192.168.0.1-192.168.0.3]",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=53,dport=54)`);
	assert(built.ok);
	char[64] buf;
	Registry reg = registry::create_default_registry();

	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);
	FixupOptions options;
	options.ipv4_checksum = FixupMode.HARDWARE_OFFLOAD;
	options.udp_checksum = FixupMode.HARDWARE_OFFLOAD;
	FixupPlanResult plan = serializer::plan_packet_fixups(built.packet, &reg, buf[..], serialize.packet_len, options);
	assert(plan.ok);
	PayloadFieldModifier* modifier = find_modifier(serialize, "IP", "src");
	assert(modifier != null);

	String error = "";
	assert(modifier.apply(buf[..], 2, &error));
	FixupResult fixup = serializer::apply_fixup_plan(buf[..], plan.plan);

	assert(fixup.ok);
	assert(fixup.offload.layer3 == OffloadLayer3.IPV4);
	assert(fixup.offload.ipv4_checksum);
	assert(fixup.offload.udp_checksum);
	assert(fixup.offload.l2_len == 14);
	assert(fixup.offload.l3_len == 20);
	assert(fixup.offload.l4_len == 8);
	assert(u16_at(buf[..], 24) == 0);
	uint pseudo = serializer::ipv4_pseudo_sum(buf[..], 14, (char)17, (ushort)8);
	assert(u16_at(buf[..], 40) == serializer::fold_checksum(pseudo));
}

fn void test_software_fixup_updates_lengths_and_checksums() @test {
	BuildResult built = build_default(
		`Ether(type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=53,dport=54)`);
	assert(built.ok);
	char[64] buf;
	Registry reg = registry::create_default_registry();

	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);
	FixupResult fixup = serializer::fixup_packet(built.packet, &reg, buf[..], serialize.packet_len);

	assert(fixup.ok);
	assert(u16_at(buf[..], 16) == 28);
	assert(u16_at(buf[..], 38) == 8);
	assert(serializer::fold_checksum(serializer::checksum_sum(buf[14:20])) == 0xffff);
	uint pseudo = serializer::ipv4_pseudo_sum(buf[..], 14, (char)17, (ushort)8);
	assert(serializer::fold_checksum(pseudo + serializer::checksum_sum(buf[34:8])) == 0xffff);
}

fn void test_hardware_fixup_records_offload_request() @test {
	BuildResult built = build_default(
		`Ether(type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",ttl=64,proto=17)/UDP(sport=53,dport=54)`);
	assert(built.ok);
	char[64] buf;
	Registry reg = registry::create_default_registry();
	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);

	FixupOptions options;
	options.ipv4_checksum = FixupMode.HARDWARE_OFFLOAD;
	options.udp_checksum = FixupMode.HARDWARE_OFFLOAD;
	FixupResult fixup = serializer::fixup_packet(built.packet, &reg, buf[..], serialize.packet_len, options);

	assert(fixup.ok);
	assert(fixup.offload.layer3 == OffloadLayer3.IPV4);
	assert(fixup.offload.ipv4_checksum);
	assert(fixup.offload.udp_checksum);
	assert(!fixup.offload.tcp_checksum);
	assert(fixup.offload.l2_len == 14);
	assert(fixup.offload.l3_len == 20);
	assert(fixup.offload.l4_len == 8);
	assert(u16_at(buf[..], 24) == 0);
	assert(u16_at(buf[..], 40) != 0);
}

fn void test_disabled_checksum_mode_preserves_explicit_checksum_fields() @test {
	BuildResult built = build_default(
		`Ether(type=2048)/IP(src="192.168.0.1",dst="192.168.0.2",chksum=9,proto=17)/UDP(sport=53,dport=54,chksum=10)`);
	assert(built.ok);
	char[64] buf;
	Registry reg = registry::create_default_registry();
	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);

	FixupOptions options;
	options.ipv4_checksum = FixupMode.DISABLED;
	options.udp_checksum = FixupMode.DISABLED;
	FixupResult fixup = serializer::fixup_packet(built.packet, &reg, buf[..], serialize.packet_len, options);

	assert(fixup.ok);
	assert(u16_at(buf[..], 16) == 28);
	assert(u16_at(buf[..], 38) == 8);
	assert(u16_at(buf[..], 24) == 9);
	assert(u16_at(buf[..], 40) == 10);
}

// Guards against the single-`layer4` plan regression: a VXLAN packet carries an
// outer IPv4/UDP plus an inner IPv4/TCP, and the outer UDP length must still be
// written even though a later (inner) TCP header exists.
fn void test_fixup_writes_outer_udp_length_alongside_inner_tcp() @test {
	BuildResult built = build_default(
		`Ether(dst="ff:ff:ff:ff:ff:ff",src="02:64:74:61:70:00")/IP(src="203.0.113.1",dst="203.0.113.2")/UDP()/VXLAN(vni=42)/Ether(dst="02:00:00:00:00:02",src="02:00:00:00:00:01")/IP(src="10.10.0.1",dst="10.10.0.2")/TCP(sport=2000,dport=2001,flags=2)`);
	assert(built.ok);
	char[128] buf;
	Registry reg = registry::create_default_registry();
	SerializeResult serialize = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(serialize.ok);
	assert(serialize.packet_len == 104);

	FixupResult fixup = serializer::fixup_packet(built.packet, &reg, buf[..], serialize.packet_len);
	assert(fixup.ok);

	// Outer IPv4 total length @16 and outer UDP length @38 are both written.
	assert(u16_at(buf[..], 16) == 90);
	assert(u16_at(buf[..], 38) == 70);
	// Inner TCP checksum @100 is computed (non-zero).
	assert(u16_at(buf[..], 100) != 0);
}
