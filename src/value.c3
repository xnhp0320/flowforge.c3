module flowforge::value;
import std::net;

faultdef INVALID_MAC, INVALID_IPV4, INVALID_IPV6, WRONG_KIND;

fn int hex_val(char c) {
	if (c.is_digit()) return (int)(c - '0');
	if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
	if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
	return -1;
}

struct MacAddr {
	char[6] bytes;
}

fn MacAddr mac_from_bytes(char[6] b) {
	return { .bytes = b };
}

fn MacAddr? mac_parse(String s) {
	if (s.len != 17) return INVALID_MAC~;
	char[6] bytes;
	for (usz i = 0; i < 6; i++) {
		usz base = i * 3;
		int high = hex_val(s[base]);
		int low = hex_val(s[base + 1]);
		if (high < 0 || low < 0) return INVALID_MAC~;
		if (i < 5 && s[base + 2] != ':') return INVALID_MAC~;
		bytes[i] = (char)((high << 4) | low);
	}
	return { .bytes = bytes };
}

fn String MacAddr.to_string(self) {
	return string::tformat("%02x:%02x:%02x:%02x:%02x:%02x",
		self.bytes[0], self.bytes[1], self.bytes[2],
		self.bytes[3], self.bytes[4], self.bytes[5]);
}

struct IPv4 {
	char[4] bytes;
}

fn IPv4 ipv4_from_bytes(char[4] b) {
	return { .bytes = b };
}

fn IPv4? ipv4_parse(String s) {
	net::InetAddress? addr = net::ipv4_from_str(s);
	if (catch addr) return INVALID_IPV4~;
	return { .bytes = { addr.ipv4.a, addr.ipv4.b, addr.ipv4.c, addr.ipv4.d } };
}

fn String IPv4.to_string(self) {
	return string::tformat("%d.%d.%d.%d", self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]);
}

struct IPv6 {
	char[16] bytes;
}

fn IPv6 ipv6_from_bytes(char[16] b) {
	return { .bytes = b };
}

fn IPv6? ipv6_parse(String s) {
	net::InetAddress? addr = net::ipv6_from_str(s);
	if (catch addr) return INVALID_IPV6~;
	char[16] bytes;
	ushort[8] groups = { addr.ipv6.a, addr.ipv6.b, addr.ipv6.c, addr.ipv6.d,
		addr.ipv6.e, addr.ipv6.f, addr.ipv6.g, addr.ipv6.h };
	for (usz i = 0; i < 8; i++) {
		bytes[i * 2] = (char)(groups[i] >> 8);
		bytes[i * 2 + 1] = (char)(groups[i] & 0xFF);
	}
	return { .bytes = bytes };
}

fn String IPv6.to_string(self) {
	return string::tformat("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		(self.bytes[0] << 8) | self.bytes[1],
		(self.bytes[2] << 8) | self.bytes[3],
		(self.bytes[4] << 8) | self.bytes[5],
		(self.bytes[6] << 8) | self.bytes[7],
		(self.bytes[8] << 8) | self.bytes[9],
		(self.bytes[10] << 8) | self.bytes[11],
		(self.bytes[12] << 8) | self.bytes[13],
		(self.bytes[14] << 8) | self.bytes[15]);
}

struct IPv4Range {
	IPv4 first;
	IPv4 last;
}

struct IPv6Range {
	IPv6 first;
	IPv6 last;
}

struct UIntRange {
	ulong first;
	ulong last;
}

enum ConstructorValueKind {
	UINT,
	MAC,
	IPV4,
	IPV6,
	IPV4_RANGE,
	IPV6_RANGE,
	IPV4_RANGES,
	IPV6_RANGES,
	UINT_RANGES,
}

struct ConstructorValue {
	ConstructorValueKind kind;
	ulong uint_val;
	MacAddr mac_val;
	IPv4 ipv4_val;
	IPv6 ipv6_val;
	IPv4Range ipv4_range_val;
	IPv6Range ipv6_range_val;
	IPv4Range[] ipv4_ranges_val;
	IPv6Range[] ipv6_ranges_val;
	UIntRange[] uint_ranges_val;
}

fn ConstructorValue cv_uint(ulong v) {
	return { .kind = ConstructorValueKind.UINT, .uint_val = v };
}

fn ConstructorValue cv_mac(MacAddr m) {
	return { .kind = ConstructorValueKind.MAC, .mac_val = m };
}

fn ConstructorValue cv_ipv4(IPv4 ip) {
	return { .kind = ConstructorValueKind.IPV4, .ipv4_val = ip };
}

fn ConstructorValue cv_ipv6(IPv6 ip) {
	return { .kind = ConstructorValueKind.IPV6, .ipv6_val = ip };
}

fn ConstructorValue cv_ipv4_range(IPv4Range r) {
	return { .kind = ConstructorValueKind.IPV4_RANGE, .ipv4_range_val = r };
}

fn ConstructorValue cv_ipv6_range(IPv6Range r) {
	return { .kind = ConstructorValueKind.IPV6_RANGE, .ipv6_range_val = r };
}

fn ConstructorValue cv_ipv4_ranges(IPv4Range[] r) {
	return { .kind = ConstructorValueKind.IPV4_RANGES, .ipv4_ranges_val = r };
}

fn ConstructorValue cv_ipv6_ranges(IPv6Range[] r) {
	return { .kind = ConstructorValueKind.IPV6_RANGES, .ipv6_ranges_val = r };
}

fn ConstructorValue cv_uint_ranges(UIntRange[] r) {
	return { .kind = ConstructorValueKind.UINT_RANGES, .uint_ranges_val = r };
}

fn ulong? cv_as_uint(ConstructorValue v) {
	if (v.kind != ConstructorValueKind.UINT) return WRONG_KIND~;
	return v.uint_val;
}

fn bool cv_equals(ConstructorValue a, ConstructorValue b) {
	if (a.kind != b.kind) return false;
	switch (a.kind) {
		case UINT:
			return a.uint_val == b.uint_val;
		case MAC:
			return a.mac_val.bytes == b.mac_val.bytes;
		case IPV4:
			return a.ipv4_val.bytes == b.ipv4_val.bytes;
		case IPV6:
			return a.ipv6_val.bytes == b.ipv6_val.bytes;
		case IPV4_RANGE:
			return ipv4_range_equals(a.ipv4_range_val, b.ipv4_range_val);
		case IPV6_RANGE:
			return ipv6_range_equals(a.ipv6_range_val, b.ipv6_range_val);
		case IPV4_RANGES:
			if (a.ipv4_ranges_val.len != b.ipv4_ranges_val.len) return false;
			for (usz i = 0; i < a.ipv4_ranges_val.len; i++) {
				if (!ipv4_range_equals(a.ipv4_ranges_val[i], b.ipv4_ranges_val[i])) return false;
			}
			return true;
		case IPV6_RANGES:
			if (a.ipv6_ranges_val.len != b.ipv6_ranges_val.len) return false;
			for (usz i = 0; i < a.ipv6_ranges_val.len; i++) {
				if (!ipv6_range_equals(a.ipv6_ranges_val[i], b.ipv6_ranges_val[i])) return false;
			}
			return true;
		case UINT_RANGES:
			if (a.uint_ranges_val.len != b.uint_ranges_val.len) return false;
			for (usz i = 0; i < a.uint_ranges_val.len; i++) {
				if (a.uint_ranges_val[i].first != b.uint_ranges_val[i].first) return false;
				if (a.uint_ranges_val[i].last != b.uint_ranges_val[i].last) return false;
			}
			return true;
	}
}

fn bool ipv4_range_equals(IPv4Range a, IPv4Range b) {
	return a.first.bytes == b.first.bytes && a.last.bytes == b.last.bytes;
}

fn bool ipv6_range_equals(IPv6Range a, IPv6Range b) {
	return a.first.bytes == b.first.bytes && a.last.bytes == b.last.bytes;
}
