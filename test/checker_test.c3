module flowforge_checker_test @test;
import flowforge::ast;
import flowforge::checker;
import flowforge::registry;
import flowforge::testutil;

fn void test_checker_all_known_headers() @test {
	Packet pkt = testutil::must_parse("Ether()/VLAN()/IP()/IPv6()/TCP()/UDP()/ICMP()/VXLAN()/Payload()/IPOption_EOL()/IPOption_NOP()/TCPOption_EOL()/TCPOption_NOP()/TCPOption_MSS()/TCPOption_WS()/TCPOption_SACKPermitted()/TCPOption_Timestamp()");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
	assert(result.warnings.len == 0);
}

fn void test_checker_unknown_header() @test {
	Packet pkt = testutil::must_parse("Ether()/BadProtocol()");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("BadProtocol"));
}

fn void test_checker_known_attrs_no_warnings() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"ff:ff:ff:ff:ff:ff\",src=\"00:11:22:33:44:55\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 0);
}

fn void test_checker_unknown_attribute_warning() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"ff:ff:ff:ff:ff:ff\",foobar=42)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 1);
	assert(result.warnings[0].contains("foobar"));
	assert(result.warnings[0].contains("Ether"));
}

fn void test_checker_mixed_errors_and_warnings() @test {
	Packet pkt = testutil::must_parse("Ether(unknown_attr=1)/BadProto(dport=80)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.warnings.len == 1);
}

fn void test_checker_scapy_style_semantic_check() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"ff:ff:ff:ff:ff:ff\")/IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")/TCP(dport=80,sport=1234)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
	assert(result.warnings.len == 0);
}

fn void test_checker_tcp_all_attrs() @test {
	Packet pkt = testutil::must_parse("TCP(sport=1,dport=2,seq=3,ack=4,dataofs=5,reserved=6,flags=7,window=8,chksum=9,urgptr=10)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 0);
}

fn void test_checker_udp_attrs() @test {
	Packet pkt = testutil::must_parse("UDP(sport=53,dport=53,len=128,chksum=0)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 0);
}

fn void test_checker_icmp_attrs() @test {
	Packet pkt = testutil::must_parse("ICMP(type=8,code=0,chksum=0xffff,id=1,seq=1)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 0);
}

fn void test_checker_vlan_attrs() @test {
	Packet pkt = testutil::must_parse("VLAN(prio=7,dei=1,vlan=4095,type=0x0800)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 0);
}

fn void test_checker_vxlan_attrs() @test {
	Packet pkt = testutil::must_parse("VXLAN(flags=0x08,reserved=0,vni=100,reserved2=0)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 0);
}

fn void test_checker_custom_header_registration() @test {
	Packet pkt = testutil::must_parse("MyProto(field1=1,field2=2)");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyProto",
		{ "field1", "field2", "field3" },
		{ "b64", "b64", "b64" },
		{});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
	assert(result.warnings.len == 0);
}

fn void test_checker_custom_header_unknown_attr() @test {
	Packet pkt = testutil::must_parse("MyProto(bad_field=1)");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyProto",
		{ "field1", "field2" },
		{ "b64", "b64" },
		{});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 1);
}

fn void test_checker_validate_or_exit_does_not_exit_on_valid() @test {
	Packet pkt = testutil::must_parse("Ether()/IP()");
	Checker checker = checker::checker_with_default();
	checker.validate_or_exit(pkt);
}

fn void test_checker_valid_mac_addr() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"ff:ff:ff:ff:ff:ff\",src=\"00:11:22:33:44:55\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_invalid_mac_addr_too_short() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"ff:ff:ff\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("dst"));
}

fn void test_checker_invalid_mac_addr_non_hex() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"gg:ff:ff:ff:ff:ff\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("dst"));
}

fn void test_checker_invalid_mac_addr_missing_colon() @test {
	Packet pkt = testutil::must_parse("Ether(dst=\"ffffff:ff:ff:ff:ff\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_valid_ipv4_addr() @test {
	Packet pkt = testutil::must_parse("IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_invalid_ipv4_bad_octet() @test {
	Packet pkt = testutil::must_parse("IP(src=\"256.0.0.1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("src"));
}

fn void test_checker_invalid_ipv4_too_few_dots() @test {
	Packet pkt = testutil::must_parse("IP(src=\"192.168.1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_invalid_ipv4_non_numeric() @test {
	Packet pkt = testutil::must_parse("IP(src=\"abc.def.ghi.jkl\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
}

fn void test_checker_valid_ipv6_addr() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001:db8::1\",dst=\"fe80::1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_valid_ipv6_full_addr() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001:0db8:0000:0000:0000:ff00:0042:8329\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_valid_ipv6_loopback() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"::1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_invalid_ipv6_double_double_colon() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001::10::1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_invalid_ipv6_bad_hex_group() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001:xyz1::1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
}

fn void test_checker_invalid_ipv6_too_many_groups() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"1:2:3:4::5:6:7:8:9\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
}

fn void test_checker_mac_addr_must_be_string() @test {
	Packet pkt = testutil::must_parse("Ether(dst=123456)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors[0].contains("string"));
}

fn void test_checker_ip_both_src_and_dst_valid() @test {
	Packet pkt = testutil::must_parse("IP(src=\"1.2.3.4\",dst=\"5.6.7.8\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_unknown_attr_skipped_no_format_error() @test {
	Packet pkt = testutil::must_parse("Ether(unk=\"not-a-mac-addr-but-unknown-attr\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.warnings.len == 1);
	assert(result.errors.len == 0);
}

fn void test_checker_custom_type_registration() @test {
	Packet pkt = testutil::must_parse("MyProto(addr=\"hello\")");
	Registry reg = registry::create_default_registry();
	reg.add_failing_type("always_fails", "always fails");
	reg.add_header("MyProto", { "addr" }, { "always_fails" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("always fails"));
}

fn void test_checker_bit_field_in_range() @test {
	Packet pkt = testutil::must_parse("UDP(sport=53,dport=53,len=128,chksum=0)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_field_out_of_range() @test {
	Packet pkt = testutil::must_parse("TCP(dport=65536)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("dport"));
	assert(result.errors[0].contains("16"));
}

fn void test_checker_bit_field_negative() @test {
	Packet pkt = testutil::must_parse("TCP(sport=-1)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_bit_field_at_max() @test {
	Packet pkt = testutil::must_parse("TCP(sport=65535,dport=65535)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_field_b1_zero() @test {
	Packet pkt = testutil::must_parse("ICMP(type=0)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
}

fn void test_checker_bit_field_b64() @test {
	Packet pkt = testutil::must_parse("MyHdr(field=9223372036854775807)");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr", { "field" }, { "b64" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_field_must_be_integer() @test {
	Packet pkt = testutil::must_parse("IP(ttl=\"not-a-number\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors[0].contains("expected integer"));
}

fn void test_checker_port_fields_accept_ranges() @test {
	Packet pkt = testutil::must_parse("TCP(sport=\"[10000-10002]\",dport=\"[20000-20001]\")/UDP(sport=\"[30000-30002]\",dport=53)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_field_b4_max() @test {
	Packet pkt = testutil::must_parse("IP(version=15,ihl=15)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
}

fn void test_checker_bit_field_b4_overflow() @test {
	Packet pkt = testutil::must_parse("IP(version=16,ihl=16)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 2);
}

fn void test_checker_bit_field_b20_at_max() @test {
	Packet pkt = testutil::must_parse("IPv6(fl=1048575)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
}

fn void test_checker_bit_field_b20_overflow() @test {
	Packet pkt = testutil::must_parse("IPv6(fl=1048576)");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("20"));
}

fn void test_checker_bit_range_list_accepts_scalar_integer() @test {
	Packet pkt = testutil::must_parse("MyHdr(field=65535)");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr", { "field" }, { "b16_ranges" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_range_list_accepts_scalar_string() @test {
	Packet pkt = testutil::must_parse("MyHdr(field=\"65535\")");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr", { "field" }, { "b16_ranges" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_range_list_accepts_range_and_list() @test {
	Packet pkt = testutil::must_parse("MyHdr(a=\"1-2\",b=\"[1,2]\",c=\"[1-2, 3-4]\")");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr",
		{ "a", "b", "c" },
		{ "b16_ranges", "b16_ranges", "b16_ranges" },
		{});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_range_list_accepts_hex_and_binary() @test {
	Packet pkt = testutil::must_parse("MyHdr(a=0b1010,b=\"0x10-0b10010\",c=\"[0x1f, 0b100000-0x21]\")");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr",
		{ "a", "b", "c" },
		{ "b16_ranges", "b16_ranges", "b16_ranges" },
		{});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_bit_range_list_rejects_out_of_width_value() @test {
	Packet pkt = testutil::must_parse("MyHdr(field=\"65536\")");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr", { "field" }, { "b16_ranges" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("16 bits"));
}

fn void test_checker_bit_range_list_rejects_negative_value() @test {
	Packet pkt = testutil::must_parse("MyHdr(field=-1)");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr", { "field" }, { "b16_ranges" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_bit_range_list_rejects_reversed_range() @test {
	Packet pkt = testutil::must_parse("MyHdr(field=\"2-1\")");
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr", { "field" }, { "b16_ranges" }, {});
	Checker checker = { .registry = &reg };
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("greater"));
}

fn void test_checker_bit_range_list_rejects_malformed_lists() @test {
	Registry reg = registry::create_default_registry();
	reg.add_header("MyHdr",
		{ "empty", "trailing" },
		{ "b16_ranges", "b16_ranges" },
		{});
	Checker checker = { .registry = &reg };
	Packet pkt = testutil::must_parse("MyHdr(empty=\"[]\",trailing=\"[1,]\")");
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 2);
}

fn void test_checker_ipv4_single_address_in_range_type() @test {
	Packet pkt = testutil::must_parse("IP(src=\"192.168.1.1\",dst=\"10.0.0.1\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv4_cidr() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.0/24\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv4_cidr_mask_zero() @test {
	Packet pkt = testutil::must_parse("IP(src=\"0.0.0.0/0\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
}

fn void test_checker_ipv4_cidr_mask32() @test {
	Packet pkt = testutil::must_parse("IP(src=\"1.2.3.4/32\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
}

fn void test_checker_ipv4_cidr_mask_out_of_range() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.0/33\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("33"));
}

fn void test_checker_ipv4_cidr_bad_prefix() @test {
	Packet pkt = testutil::must_parse("IP(src=\"256.0.0.0/24\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_ipv4_cidr_empty_mask() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.0/\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
}

fn void test_checker_ipv4_cidr_non_numeric_mask() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.0/abc\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
}

fn void test_checker_ipv4_range() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.1-10.0.0.255\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv4_range_list() @test {
	Packet pkt = testutil::must_parse("IP(src=\"[10.0.0.1, 10.0.0.0/24, 10.0.1.1-10.0.1.255]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv4_range_list_single_element() @test {
	Packet pkt = testutil::must_parse("IP(src=\"[10.0.0.1]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv4_range_list_bad_element() @test {
	Packet pkt = testutil::must_parse("IP(src=\"[10.0.0.1, 10.0.0.256]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("index 1"));
}

fn void test_checker_ipv4_range_list_empty() @test {
	Packet pkt = testutil::must_parse("IP(src=\"[]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_ipv4_range_list_trailing_comma() @test {
	Packet pkt = testutil::must_parse("IP(src=\"[10.0.0.1,]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_ipv4_range_bad_left() @test {
	Packet pkt = testutil::must_parse("IP(src=\"256.0.0.1-10.0.0.255\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_ipv4_range_bad_right() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.1-10.0.0.256\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_ipv4_range_empty_right() @test {
	Packet pkt = testutil::must_parse("IP(src=\"10.0.0.1-\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
}

fn void test_checker_ipv6_cidr() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001:db8::/48\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv6_cidr_mask128() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"::1/128\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
}

fn void test_checker_ipv6_cidr_mask_out_of_range() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001:db8::/129\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(!result.ok);
	assert(result.errors.len == 1);
}

fn void test_checker_ipv6_range() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"2001:db8::1-2001:db8::ff\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}

fn void test_checker_ipv6_range_list() @test {
	Packet pkt = testutil::must_parse("IPv6(src=\"[2001:db8::1, 2001:db8::/48, 2001:db8::1-2001:db8::ff]\")");
	Checker checker = checker::checker_with_default();
	CheckResult result = checker.check(pkt);
	assert(result.ok);
	assert(result.errors.len == 0);
}
