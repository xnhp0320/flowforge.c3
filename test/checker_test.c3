module flowforge_checker_test @test;
import flowforge::ast;
import flowforge::checker;
import flowforge::registry;
import flowforge::testutil;

fn void test_checker_all_known_headers() @test {
	CheckResult result = testutil::check_default("Ether()/VLAN()/IP()/IPv6()/TCP()/UDP()/ICMP()/VXLAN()/Payload()/IPOption_EOL()/IPOption_NOP()/TCPOption_EOL()/TCPOption_NOP()/TCPOption_MSS()/TCPOption_WS()/TCPOption_SACKPermitted()/TCPOption_Timestamp()");
	assert(result.ok());
	assert(result.errors.len() == 0);
	assert(result.warnings.len() == 0);
}

fn void test_checker_unknown_header() @test {
	CheckResult result = testutil::check_default("Ether()/BadProtocol()");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("BadProtocol"));
}

fn void test_checker_known_attrs_no_warnings() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"ff:ff:ff:ff:ff:ff\",src=\"00:11:22:33:44:55\")");
	assert(result.ok());
	assert(result.warnings.len() == 0);
}

fn void test_checker_unknown_attribute_warning() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"ff:ff:ff:ff:ff:ff\",foobar=42)");
	assert(result.ok());
	assert(result.warnings.len() == 1);
	assert(result.warnings[0].contains("foobar"));
	assert(result.warnings[0].contains("Ether"));
}

fn void test_checker_mixed_errors_and_warnings() @test {
	CheckResult result = testutil::check_default("Ether(unknown_attr=1)/BadProto(dport=80)");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.warnings.len() == 1);
}

fn void test_checker_scapy_style_semantic_check() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")/TCP(dport=80,sport=1234)");
	assert(result.ok());
	assert(result.errors.len() == 0);
	assert(result.warnings.len() == 0);
}

fn void test_checker_tcp_all_attrs() @test {
	CheckResult result = testutil::check_default("TCP(sport=1,dport=2,seq=3,ack=4,dataofs=5,reserved=6,flags=7,window=8,chksum=9,urgptr=10)");
	assert(result.ok());
	assert(result.warnings.len() == 0);
}

fn void test_checker_udp_attrs() @test {
	CheckResult result = testutil::check_default("UDP(sport=53,dport=53,len=128,chksum=0)");
	assert(result.ok());
	assert(result.warnings.len() == 0);
}

fn void test_checker_icmp_attrs() @test {
	CheckResult result = testutil::check_default("ICMP(type=8,code=0,chksum=0xffff,id=1,seq=1)");
	assert(result.ok());
	assert(result.warnings.len() == 0);
}

fn void test_checker_vlan_attrs() @test {
	CheckResult result = testutil::check_default("VLAN(prio=7,dei=1,vlan=4095,type=0x0800)");
	assert(result.ok());
	assert(result.warnings.len() == 0);
}

fn void test_checker_vxlan_attrs() @test {
	CheckResult result = testutil::check_default("VXLAN(flags=0x08,reserved=0,vni=100,reserved2=0)");
	assert(result.ok());
	assert(result.warnings.len() == 0);
}

fn void test_checker_custom_header_registration() @test {
	CheckResult result = testutil::check_with_header("MyProto(field1=1,field2=2)", "MyProto",
		{ "field1", "field2", "field3" },
		{ "b64", "b64", "b64" });
	assert(result.ok());
	assert(result.errors.len() == 0);
	assert(result.warnings.len() == 0);
}

fn void test_checker_custom_header_unknown_attr() @test {
	CheckResult result = testutil::check_with_header("MyProto(bad_field=1)", "MyProto",
		{ "field1", "field2" },
		{ "b64", "b64" });
	assert(result.ok());
	assert(result.warnings.len() == 1);
}

fn void test_checker_validate_or_exit_does_not_exit_on_valid() @test {
	Checker checker = checker::checker_with_default();
	checker.validate_or_exit(testutil::must_parse("Ether()/IP()"));
}

fn void test_checker_valid_mac_addr() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"ff:ff:ff:ff:ff:ff\",src=\"00:11:22:33:44:55\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_invalid_mac_addr_too_short() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"ff:ff:ff\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("dst"));
}

fn void test_checker_invalid_mac_addr_non_hex() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"gg:ff:ff:ff:ff:ff\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("dst"));
}

fn void test_checker_invalid_mac_addr_missing_colon() @test {
	CheckResult result = testutil::check_default("Ether(dst=\"ffffff:ff:ff:ff:ff\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_valid_ipv4_addr() @test {
	CheckResult result = testutil::check_default("IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_invalid_ipv4_bad_octet() @test {
	CheckResult result = testutil::check_default("IP(src=\"256.0.0.1\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("src"));
}

fn void test_checker_invalid_ipv4_too_few_dots() @test {
	CheckResult result = testutil::check_default("IP(src=\"192.168.1\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_invalid_ipv4_non_numeric() @test {
	CheckResult result = testutil::check_default("IP(src=\"abc.def.ghi.jkl\")");
	assert(!result.ok());
}

fn void test_checker_valid_ipv6_addr() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001:db8::1\",dst=\"fe80::1\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_valid_ipv6_full_addr() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001:0db8:0000:0000:0000:ff00:0042:8329\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_valid_ipv6_loopback() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"::1\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_invalid_ipv6_double_double_colon() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001::10::1\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_invalid_ipv6_bad_hex_group() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001:xyz1::1\")");
	assert(!result.ok());
}

fn void test_checker_invalid_ipv6_too_many_groups() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"1:2:3:4::5:6:7:8:9\")");
	assert(!result.ok());
}

fn void test_checker_mac_addr_must_be_string() @test {
	CheckResult result = testutil::check_default("Ether(dst=123456)");
	assert(!result.ok());
	assert(result.errors[0].contains("string"));
}

fn void test_checker_ip_both_src_and_dst_valid() @test {
	CheckResult result = testutil::check_default("IP(src=\"1.2.3.4\",dst=\"5.6.7.8\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_unknown_attr_skipped_no_format_error() @test {
	CheckResult result = testutil::check_default("Ether(unk=\"not-a-mac-addr-but-unknown-attr\")");
	assert(result.ok());
	assert(result.warnings.len() == 1);
	assert(result.errors.len() == 0);
}

fn void test_checker_custom_type_registration() @test {
	Registry reg = registry::create_default_registry();
	reg.add_failing_type("always_fails", "always fails");
	reg.add_header("MyProto", { "addr" }, { "always_fails" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(testutil::must_parse("MyProto(addr=\"hello\")"));
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("always fails"));
}

fn void test_checker_bit_field_in_range() @test {
	CheckResult result = testutil::check_default("UDP(sport=53,dport=53,len=128,chksum=0)");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_field_out_of_range() @test {
	CheckResult result = testutil::check_default("TCP(dport=65536)");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("dport"));
	assert(result.errors[0].contains("16"));
}

fn void test_checker_bit_field_negative() @test {
	CheckResult result = testutil::check_default("TCP(sport=-1)");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_bit_field_at_max() @test {
	CheckResult result = testutil::check_default("TCP(sport=65535,dport=65535)");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_field_b1_zero() @test {
	CheckResult result = testutil::check_default("ICMP(type=0)");
	assert(result.ok());
}

fn void test_checker_bit_field_b64() @test {
	CheckResult result = testutil::check_with_header("MyHdr(field=9223372036854775807)", "MyHdr", { "field" }, { "b64" });
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_field_must_be_integer() @test {
	CheckResult result = testutil::check_default("IP(ttl=\"not-a-number\")");
	assert(!result.ok());
	assert(result.errors[0].contains("expected integer"));
}

fn void test_checker_port_fields_accept_ranges() @test {
	CheckResult result = testutil::check_default("TCP(sport=\"[10000-10002]\",dport=\"[20000-20001]\")/UDP(sport=\"[30000-30002]\",dport=53)");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_field_b4_max() @test {
	CheckResult result = testutil::check_default("IP(version=15,ihl=15)");
	assert(result.ok());
}

fn void test_checker_bit_field_b4_overflow() @test {
	CheckResult result = testutil::check_default("IP(version=16,ihl=16)");
	assert(!result.ok());
	assert(result.errors.len() == 2);
}

fn void test_checker_bit_field_b20_at_max() @test {
	CheckResult result = testutil::check_default("IPv6(fl=1048575)");
	assert(result.ok());
}

fn void test_checker_bit_field_b20_overflow() @test {
	CheckResult result = testutil::check_default("IPv6(fl=1048576)");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("20"));
}

fn void test_checker_bit_range_list_accepts_scalar_integer() @test {
	CheckResult result = testutil::check_with_header("MyHdr(field=65535)", "MyHdr", { "field" }, { "b16_ranges" });
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_range_list_accepts_scalar_string() @test {
	CheckResult result = testutil::check_with_header("MyHdr(field=\"65535\")", "MyHdr", { "field" }, { "b16_ranges" });
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_range_list_accepts_range_and_list() @test {
	CheckResult result = testutil::check_with_header("MyHdr(a=\"1-2\",b=\"[1,2]\",c=\"[1-2, 3-4]\")", "MyHdr",
		{ "a", "b", "c" },
		{ "b16_ranges", "b16_ranges", "b16_ranges" });
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_bit_range_list_accepts_hex_and_binary() @test {
	CheckResult result = testutil::check_with_header("MyHdr(a=0b1010,b=\"0x10-0b10010\",c=\"[0x1f, 0b100000-0x21]\")", "MyHdr",
		{ "a", "b", "c" },
		{ "b16_ranges", "b16_ranges", "b16_ranges" });
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_accepts_range_steps_for_all_range_types() @test {
	Packet pkt = testutil::must_parse(
		"IP(src=\"10.0.0.1-10.0.0.100(step=2)\")/IPv6(src=\"2001:db8::1-2001:db8::ff(step=2)\")/TCP(sport=\"1-100(step=2)\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len() == 0);
}

fn void test_checker_accepts_per_range_steps_in_lists() @test {
	Packet pkt = testutil::must_parse("TCP(sport=\"[1-10(step=2), 20-30(step=3)]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len() == 0);
}

fn void test_checker_accepts_rand_for_all_explicit_range_types() @test {
	Packet pkt = testutil::must_parse(
		"IP(src=\"10.0.0.1-10.0.0.100(rand)\")/IPv6(src=\"2001:db8::1-2001:db8::ff(rand)\")/TCP(sport=\"1-100(rand)\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len() == 0);
}

fn void test_checker_rejects_invalid_range_steps() @test {
	String[] values = {
		"1-10(step=0)",
		"1-10(step=-2)",
		"1-10(step=)",
		"1-10(step=0x2)",
		"1-10(foo=2)",
		"1-10(step=2)(step=3)",
		"1-10(step=2, step=3)",
		"1-10(step=2, rand)",
		"1-10(rand, step=2)",
		"1-10(rand=1)",
		"1-10(rand, rand)",
		"1-10(step=18446744073709551616)",
		"1(step=2)",
	};
	foreach (raw : values) {
		Packet pkt = testutil::must_parse(string::tformat("TCP(sport=\"%s\")", raw));
		Checker checker = checker::checker_with_default();
		CheckResult result = checker.check(pkt);
		assert(!result.ok);
		assert(result.errors.len() == 1);
	}
}

fn void test_checker_rejects_range_step_on_cidr() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.0/24(step=2)\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("CIDR"));
}

fn void test_checker_bit_range_list_rejects_out_of_width_value() @test {
	CheckResult result = testutil::check_with_header("MyHdr(field=\"65536\")", "MyHdr", { "field" }, { "b16_ranges" });
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("16 bits"));
}

fn void test_checker_bit_range_list_rejects_negative_value() @test {
	CheckResult result = testutil::check_with_header("MyHdr(field=-1)", "MyHdr", { "field" }, { "b16_ranges" });
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_bit_range_list_rejects_reversed_range() @test {
	CheckResult result = testutil::check_with_header("MyHdr(field=\"2-1\")", "MyHdr", { "field" }, { "b16_ranges" });
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("greater"));
}

fn void test_checker_bit_range_list_rejects_malformed_lists() @test {
	CheckResult result = testutil::check_with_header("MyHdr(empty=\"[]\",trailing=\"[1,]\")", "MyHdr",
		{ "empty", "trailing" },
		{ "b16_ranges", "b16_ranges" });
	assert(!result.ok());
	assert(result.errors.len() == 2);
}

fn void test_checker_ipv4_single_address_in_range_type() @test {
	CheckResult result = testutil::check_default("IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv4_cidr() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.0/24\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv4_cidr_mask_zero() @test {
	CheckResult result = testutil::check_default("IP(src=\"0.0.0.0/0\")");
	assert(result.ok());
}

fn void test_checker_ipv4_cidr_mask32() @test {
	CheckResult result = testutil::check_default("IP(src=\"1.2.3.4/32\")");
	assert(result.ok());
}

fn void test_checker_ipv4_cidr_mask_out_of_range() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.0/33\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("33"));
}

fn void test_checker_ipv4_cidr_bad_prefix() @test {
	CheckResult result = testutil::check_default("IP(src=\"256.0.0.0/24\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_ipv4_cidr_empty_mask() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.0/\")");
	assert(!result.ok());
}

fn void test_checker_ipv4_cidr_non_numeric_mask() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.0/abc\")");
	assert(!result.ok());
}

fn void test_checker_ipv4_range() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.1-10.0.0.255\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv4_range_list() @test {
	CheckResult result = testutil::check_default("IP(src=\"[10.0.0.1, 10.0.0.0/24, 10.0.1.1-10.0.1.255]\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv4_range_list_single_element() @test {
	CheckResult result = testutil::check_default("IP(src=\"[10.0.0.1]\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv4_range_list_bad_element() @test {
	CheckResult result = testutil::check_default("IP(src=\"[10.0.0.1, 10.0.0.256]\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
	assert(result.errors[0].contains("index 1"));
}

fn void test_checker_ipv4_range_list_empty() @test {
	CheckResult result = testutil::check_default("IP(src=\"[]\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_ipv4_range_list_trailing_comma() @test {
	CheckResult result = testutil::check_default("IP(src=\"[10.0.0.1,]\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_ipv4_range_bad_left() @test {
	CheckResult result = testutil::check_default("IP(src=\"256.0.0.1-10.0.0.255\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_ipv4_range_bad_right() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.1-10.0.0.256\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_ipv4_range_empty_right() @test {
	CheckResult result = testutil::check_default("IP(src=\"10.0.0.1-\")");
	assert(!result.ok());
}

fn void test_checker_ipv6_cidr() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001:db8::/48\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv6_cidr_mask128() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"::1/128\")");
	assert(result.ok());
}

fn void test_checker_ipv6_cidr_mask_out_of_range() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001:db8::/129\")");
	assert(!result.ok());
	assert(result.errors.len() == 1);
}

fn void test_checker_ipv6_range() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"2001:db8::1-2001:db8::ff\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}

fn void test_checker_ipv6_range_list() @test {
	CheckResult result = testutil::check_default("IPv6(src=\"[2001:db8::1, 2001:db8::/48, 2001:db8::1-2001:db8::ff]\")");
	assert(result.ok());
	assert(result.errors.len() == 0);
}
