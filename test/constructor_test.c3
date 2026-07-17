module flowforge_constructor_test;
import flowforge::ast;
import flowforge::constructor;
import flowforge::registry;
import flowforge::value;
import flowforge::testutil;

fn BuildResult build_default(String input) {
	Registry reg = registry::create_default_registry();
	Packet pkt = testutil::must_parse(input);
	return constructor::build(&reg, pkt);
}

fn BuildResult build_with(String input, Registry* reg) {
	Packet pkt = testutil::must_parse(input);
	return constructor::build(reg, pkt);
}

fn HeaderConstructor[] hdrs(BuildResult r) {
	return (HeaderConstructor[])r.packet;
}

fn FieldConstructor get_field(HeaderConstructor h, String name) {
	foreach (f : h.fields) {
		if (f.name == name) return f;
	}
	unreachable();
}

fn OptionConstructor get_option(HeaderConstructor h, String name) {
	foreach (o : h.options) {
		if (o.name == name) return o;
	}
	unreachable();
}

fn HeaderConstructor[] pkt_option(HeaderConstructor h, String name) {
	OptionConstructor o = get_option(h, name);
	return (HeaderConstructor[])o.packet_value;
}

fn bool registration_fails(Registry* reg, String parent, String child, String target, ConstructorValue v) {
	if (catch reg.register_inference_rule(parent, child, target, v)) {
		return true;
	}
	return false;
}

fn void test_builds_defaults_and_offsets() @test {
	BuildResult result = build_default("Ether()/IP()/TCP()");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 3);

	assert(p[0].protocol == "Ether");
	assert(p[0].offset == 0);
	assert(p[0].fields.len == 3);

	assert(p[1].protocol == "IP");
	assert(p[1].offset == 14);
	assert(p[1].fields.len == 12);
	assert(get_field(p[1], "version").value.uint_val == 4);
	assert(get_field(p[1], "ihl").value.uint_val == 5);
	assert(get_field(p[1], "ttl").value.uint_val == 64);
	assert(!get_field(p[1], "ttl").explicitly_set);

	assert(p[2].protocol == "TCP");
	assert(p[2].offset == 34);
	assert(get_field(p[2], "dataofs").value.uint_val == 5);
}

fn void test_user_values_override_defaults_and_keep_order() @test {
	BuildResult result = build_default(`IP(dst="10.0.0.1",ttl=32,src="192.168.1.1")`);
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 1);

	HeaderConstructor ip = p[0];
	assert(ip.fields.len >= 12);
	assert(ip.fields[0].name == "version");
	assert(ip.fields[1].name == "ihl");
	assert(ip.fields[8].name == "proto");
	assert(ip.fields[9].name == "chksum");
	assert(ip.fields[10].name == "src");
	assert(ip.fields[11].name == "dst");

	assert(get_field(ip, "ttl").value.uint_val == 32);
	assert(get_field(ip, "ttl").explicitly_set);

	IPv4Range[] src_ranges = get_field(ip, "src").value.ipv4_ranges_val;
	assert(src_ranges.len == 1);
	assert(src_ranges[0].first.to_string() == "192.168.1.1");
	assert(src_ranges[0].last.to_string() == "192.168.1.1");
	assert(get_field(ip, "src").explicitly_set);
}

fn void test_normalizes_mac_and_ranges() @test {
	BuildResult result = build_default(`Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="[10.0.0.1, 10.0.0.0/24, 10.0.1.1-10.0.1.255]")/IPv6(src="2001:db8::/126")`);
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);

	HeaderConstructor ether = p[0];
	assert(get_field(ether, "dst").value.mac_val.to_string() == "ff:ff:ff:ff:ff:ff");

	IPv4Range[] ipv4_ranges = get_field(p[1], "src").value.ipv4_ranges_val;
	assert(ipv4_ranges.len == 3);
	assert(ipv4_ranges[0].first.to_string() == "10.0.0.1");
	assert(ipv4_ranges[0].last.to_string() == "10.0.0.1");
	assert(ipv4_ranges[1].first.to_string() == "10.0.0.0");
	assert(ipv4_ranges[1].last.to_string() == "10.0.0.255");
	assert(ipv4_ranges[2].first.to_string() == "10.0.1.1");
	assert(ipv4_ranges[2].last.to_string() == "10.0.1.255");

	IPv6Range[] ipv6_ranges = get_field(p[2], "src").value.ipv6_ranges_val;
	assert(ipv6_ranges.len == 1);
	assert(ipv6_ranges[0].first.to_string() == "2001:0db8:0000:0000:0000:0000:0000:0000");
	assert(ipv6_ranges[0].last.to_string() == "2001:0db8:0000:0000:0000:0000:0000:0003");
}

fn void test_vlan_offsets_and_fields() @test {
	BuildResult result = build_default("Ether()/VLAN()/IP()");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 3);

	assert(p[0].protocol == "Ether");
	assert(p[0].offset == 0);
	assert(p[1].protocol == "VLAN");
	assert(p[1].offset == 14);
	assert(p[2].protocol == "IP");
	assert(p[2].offset == 18);

	assert(p[1].fields.len == 4);
	assert(p[1].fields[0].name == "prio");
	assert(p[1].fields[1].name == "dei");
	assert(p[1].fields[2].name == "vlan");
	assert(p[1].fields[3].name == "type");
}

fn void test_infers_adjacent_protocol_fields() @test {
	BuildResult result = build_default("Ether()/VLAN()/IP()/UDP()");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 4);
	assert(result.warnings.len == 0);

	HeaderConstructor ether = p[0];
	HeaderConstructor vlan = p[1];
	HeaderConstructor ip = p[2];

	assert(get_field(ether, "type").value.uint_val == 0x8100);
	assert(!get_field(ether, "type").explicitly_set);
	assert(get_field(vlan, "type").value.uint_val == 0x0800);
	assert(!get_field(vlan, "type").explicitly_set);
	assert(get_field(ip, "proto").value.uint_val == 17);
	assert(!get_field(ip, "proto").explicitly_set);
}

fn void test_infers_ipv6_next_header() @test {
	BuildResult result = build_default("Ether()/IPv6()/TCP()");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 3);

	HeaderConstructor ether = p[0];
	HeaderConstructor ipv6 = p[1];

	assert(get_field(ether, "type").value.uint_val == 0x86dd);
	assert(!get_field(ether, "type").explicitly_set);
	assert(get_field(ipv6, "nh").value.uint_val == 6);
	assert(!get_field(ipv6, "nh").explicitly_set);
}

fn void test_explicit_protocol_field_overrides_inference_with_warning() @test {
	BuildResult result = build_default("Ether(type=0x86dd)/IP()");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 2);
	assert(result.warnings.len == 1);
	assert(result.warnings[0] == "explicit 'Ether.type' overrides inference from next header 'IP'");

	HeaderConstructor ether = p[0];
	assert(get_field(ether, "type").value.uint_val == 0x86dd);
	assert(get_field(ether, "type").explicitly_set);
}

fn void test_matching_explicit_protocol_field_does_not_warn() @test {
	BuildResult result = build_default("Ether(type=0x0800)/IP()");
	assert(result.ok);
	assert(result.warnings.len == 0);

	HeaderConstructor ether = hdrs(result)[0];
	assert(get_field(ether, "type").value.uint_val == 0x0800);
	assert(get_field(ether, "type").explicitly_set);
}

fn void test_custom_inference_rule_uses_adjacent_headers() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Outer", { registry::fld("type", "b16") });
	reg.register_header("Inner", { registry::fld("field", "b8") });
	reg.register_inference_rule("Outer", "Inner", "type", value::cv_uint(42))!!;

	BuildResult result = build_with("Outer()/Inner()", &reg);
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 2);
	assert(get_field(p[0], "type").value.uint_val == 42);
	assert(!get_field(p[0], "type").explicitly_set);
}

fn void test_invalid_inference_rule_target_fails_at_registration() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Outer", { registry::fld("type", "b16") });
	reg.register_header("Inner", { registry::fld("field", "b8") });

	assert(registration_fails(&reg, "Outer", "Inner", "unknown", value::cv_uint(42)));
}

fn void test_invalid_inference_rule_value_fails_at_registration() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Outer", { registry::fld("type", "b8") });
	reg.register_header("Inner", { registry::fld("field", "b8") });

	assert(registration_fails(&reg, "Outer", "Inner", "type", value::cv_uint(256)));
}

fn void test_vlan_values_override_defaults() @test {
	BuildResult result = build_default("VLAN(prio=7,dei=1,vlan=4095,type=0x0800)");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 1);

	HeaderConstructor vlan = p[0];
	assert(get_field(vlan, "prio").value.uint_val == 7);
	assert(get_field(vlan, "dei").value.uint_val == 1);
	assert(get_field(vlan, "vlan").value.uint_val == 4095);
	assert(get_field(vlan, "type").value.uint_val == 0x0800);
	assert(get_field(vlan, "prio").explicitly_set);
	assert(get_field(vlan, "dei").explicitly_set);
	assert(get_field(vlan, "vlan").explicitly_set);
	assert(get_field(vlan, "type").explicitly_set);
}

fn void test_vxlan_defaults_and_values() @test {
	BuildResult result = build_default("UDP()/VXLAN(vni=100)");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 2);

	HeaderConstructor vxlan = p[1];
	assert(vxlan.protocol == "VXLAN");
	assert(vxlan.offset == 8);
	assert(vxlan.fields.len == 4);
	assert(vxlan.fields[0].name == "flags");
	assert(vxlan.fields[1].name == "reserved");
	assert(vxlan.fields[2].name == "vni");
	assert(vxlan.fields[3].name == "reserved2");
	assert(get_field(vxlan, "flags").value.uint_val == 0x08);
	assert(get_field(vxlan, "vni").value.uint_val == 100);
	assert(get_field(p[0], "dport").value.uint_val == 4789);
	assert(!get_field(p[0], "dport").explicitly_set);
	assert(!get_field(vxlan, "flags").explicitly_set);
	assert(get_field(vxlan, "vni").explicitly_set);
}

fn void test_payload_length_advances_following_header_offset() @test {
	BuildResult result = build_default("Ether()/Payload(length=32)/UDP()");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 3);

	HeaderConstructor payload = p[1];
	assert(payload.protocol == "Payload");
	assert(payload.offset == 14);
	assert(payload.fields.len == 0);
	assert(payload.options.len == 1);
	assert(get_option(payload, "length").scalar_value.uint_val == 32);
	assert(get_option(payload, "length").explicitly_set);
	assert(p[2].offset == 46);
}

fn void test_payload_total_length_calculates_payload_length() @test {
	BuildResult result = build_default("Ether()/IP()/Payload(total_length=100)");
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);

	HeaderConstructor payload = p[2];
	assert(payload.offset == 34);
	assert(get_option(payload, "length").scalar_value.uint_val == 66);
	assert(!get_option(payload, "length").explicitly_set);
	assert(get_option(payload, "total_length").scalar_value.uint_val == 100);
	assert(get_option(payload, "total_length").explicitly_set);
}

fn void test_payload_total_length_rejects_too_small_packet() @test {
	BuildResult result = build_default("Ether()/IP()/Payload(total_length=20)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("smaller than preceding header length 34"));
}

fn void test_payload_rejects_conflicting_length_options() @test {
	BuildResult result = build_default("Ether()/Payload(length=10,total_length=64)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("cannot both be explicitly set"));
}

fn void test_unknown_header_fails() @test {
	BuildResult result = build_default("BadHeader()");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "unknown header: 'BadHeader'");
	assert(hdrs(result).len == 0);
}

fn void test_unknown_attribute_fails() @test {
	BuildResult result = build_default("Ether(unknown=1)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "unknown attribute 'unknown' in header 'Ether'");
}

fn void test_duplicate_attribute_fails() @test {
	BuildResult result = build_default("UDP(sport=1,sport=2)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "duplicate attribute 'sport' in header 'UDP'");
}

fn void test_name_only_attribute_fails() @test {
	BuildResult result = build_default("TCP(SYN)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "unknown attribute 'SYN' in header 'TCP'");
}

fn void test_known_name_only_attribute_fails() @test {
	BuildResult result = build_default("TCP(flags)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "attribute 'flags' in header 'TCP' requires a value");
}

fn void test_bit_width_overflow_fails() @test {
	BuildResult result = build_default("TCP(dport=65536)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("16 bits"));
}

fn void test_vlan_bit_width_overflow_fails() @test {
	BuildResult result = build_default("VLAN(vlan=4096)");
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("12 bits"));
}

fn void test_bit_ranges_default_to_scalar_zero() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("MyHdr", { registry::fld("field", "b16_ranges") });

	BuildResult result = build_with("MyHdr()", &reg);
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 1);

	FieldConstructor constructed = get_field(p[0], "field");
	assert(constructed.value.uint_val == 0);
	assert(!constructed.explicitly_set);
}

fn void test_options_are_constructed_but_not_serialized_fields() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Payload", {}, { registry::opt_scalar_default("length", "b64", value::cv_uint(64)) });

	BuildResult result = build_with("Payload(length=100)", &reg);
	assert(result.ok);
	HeaderConstructor[] p = hdrs(result);
	assert(p.len == 1);

	HeaderConstructor payload = p[0];
	assert(payload.fields.len == 0);
	assert(payload.options.len == 1);
	assert(get_option(payload, "length").scalar_value.uint_val == 100);
	assert(get_option(payload, "length").explicitly_set);
}

fn void test_options_use_defaults() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Payload", {}, { registry::opt_scalar_default("length", "b64", value::cv_uint(64)) });

	BuildResult result = build_with("Payload()", &reg);
	assert(result.ok);
	HeaderConstructor payload = hdrs(result)[0];
	assert(payload.fields.len == 0);
	assert(payload.options.len == 1);
	assert(get_option(payload, "length").scalar_value.uint_val == 64);
	assert(!get_option(payload, "length").explicitly_set);
}

fn void test_packet_valued_options_construct_nested_packet() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Outer", { registry::fld("field", "b8") }, { registry::opt_packet("children") });
	reg.register_header("InnerA", { registry::fld("a", "b8") });
	reg.register_header("InnerB", { registry::fld("b", "b16") });

	BuildResult result = build_with("Outer(children=InnerA(a=1)/InnerB(b=2))", &reg);
	assert(result.ok);
	HeaderConstructor outer = hdrs(result)[0];
	assert(outer.options.len == 1);
	assert(get_option(outer, "children").explicitly_set);

	HeaderConstructor[] children = pkt_option(outer, "children");
	assert(children.len == 2);
	assert(children[0].protocol == "InnerA");
	assert(get_field(children[0], "a").value.uint_val == 1);
	assert(children[1].protocol == "InnerB");
	assert(get_field(children[1], "b").value.uint_val == 2);
}

fn void test_packet_valued_option_rejects_scalar_value() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Outer", {}, { registry::opt_packet("children") });

	BuildResult result = build_with("Outer(children=1)", &reg);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("requires a packet value"));
}

fn void test_scalar_field_rejects_packet_value() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("Outer", { registry::fld("field", "b8") });
	reg.register_header("Inner", { registry::fld("value", "b8") });

	BuildResult result = build_with("Outer(field=Inner(value=1))", &reg);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("requires a scalar value"));
}

fn void test_bit_ranges_preserve_scalar_syntax_as_uint64() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("MyHdr", {
		registry::fld("unquoted", "b16_ranges"),
		registry::fld("quoted", "b16_ranges"),
	});

	BuildResult result = build_with(`MyHdr(unquoted=1,quoted="2")`, &reg);
	assert(result.ok);
	HeaderConstructor header = hdrs(result)[0];
	assert(get_field(header, "unquoted").value.uint_val == 1);
	assert(get_field(header, "quoted").value.uint_val == 2);
	assert(get_field(header, "unquoted").explicitly_set);
	assert(get_field(header, "quoted").explicitly_set);
}

fn void test_bit_ranges_parse_prefixed_integer_syntax() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("MyHdr", {
		registry::fld("unquoted", "b16_ranges"),
		registry::fld("quoted", "b16_ranges"),
	});

	BuildResult result = build_with(`MyHdr(unquoted=0b1010,quoted="0x10")`, &reg);
	assert(result.ok);
	HeaderConstructor header = hdrs(result)[0];
	assert(get_field(header, "unquoted").value.uint_val == 10);
	assert(get_field(header, "quoted").value.uint_val == 16);
}

fn void test_bit_ranges_normalize_range_syntax() @test {
	Registry reg = registry::create_empty_registry();
	reg.register_header("MyHdr", {
		registry::fld("range", "b16_ranges"),
		registry::fld("list", "b16_ranges"),
	});

	BuildResult result = build_with(`MyHdr(range="0x1-0b10",list="[1, 0b10-0x3]")`, &reg);
	assert(result.ok);
	HeaderConstructor header = hdrs(result)[0];

	UIntRange[] range = get_field(header, "range").value.uint_ranges_val;
	assert(range.len == 1);
	assert(range[0].first == 1);
	assert(range[0].last == 2);

	UIntRange[] list = get_field(header, "list").value.uint_ranges_val;
	assert(list.len == 2);
	assert(list[0].first == 1);
	assert(list[0].last == 1);
	assert(list[1].first == 2);
	assert(list[1].last == 3);
}
