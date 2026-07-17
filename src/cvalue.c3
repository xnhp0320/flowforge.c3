module flowforge::cvalue;
import flowforge::value;
import std::collections::list;

faultdef PARSE_ERR;

fn usz? bit_range_width_for_type_name(String type_name) {
	if (!(type_name.len && type_name[0] == 'b') || !type_name.ends_with("_ranges")) {
		return PARSE_ERR~;
	}
	String digits = type_name[1..type_name.len - 8];
	ulong? width = digits.to_ulong();
	if (catch width) return PARSE_ERR~;
	if (width < 1 || width > 64) return PARSE_ERR~;
	return (usz)width;
}

fn usz bit_width_for_type_name(String type_name) {
	if (type_name == "mac") return 48;
	if (type_name == "ipv4" || type_name == "ipv4_range" || type_name == "ipv4_ranges") return 32;
	if (type_name == "ipv6" || type_name == "ipv6_range" || type_name == "ipv6_ranges") return 128;
	usz? range_width = bit_range_width_for_type_name(type_name);
	if (try range_width) return range_width;
	if (type_name.len > 1 && type_name[0] == 'b') {
		ulong? width = type_name[1..].to_ulong();
		if (try width) return (usz)width;
	}
	return 0;
}

fn ConstructorValue default_constructor_value_for_type(String type_name) {
	if (type_name == "mac") return value::cv_mac(value::mac_from_bytes({}));
	if (type_name == "ipv4") return value::cv_ipv4(value::ipv4_from_bytes({}));
	if (type_name == "ipv6") return value::cv_ipv6(value::ipv6_from_bytes({}));
	if (type_name == "ipv4_range") {
		IPv4 zero = value::ipv4_from_bytes({});
		return value::cv_ipv4_range({ .first = zero, .last = zero });
	}
	if (type_name == "ipv6_range") {
		IPv6 zero = value::ipv6_from_bytes({});
		return value::cv_ipv6_range({ .first = zero, .last = zero });
	}
	if (type_name == "ipv4_ranges") {
		IPv4 zero = value::ipv4_from_bytes({});
		IPv4Range[] ranges = mem::temp_array(IPv4Range, 1);
		ranges[0] = { .first = zero, .last = zero };
		return value::cv_ipv4_ranges(ranges);
	}
	if (type_name == "ipv6_ranges") {
		IPv6 zero = value::ipv6_from_bytes({});
		IPv6Range[] ranges = mem::temp_array(IPv6Range, 1);
		ranges[0] = { .first = zero, .last = zero };
		return value::cv_ipv6_ranges(ranges);
	}
	return value::cv_uint(0);
}

<* Returns error string if the value does not fit; empty string means OK. *>
fn bool validate_bit_value(long integer, usz bit_width, String* error) {
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (integer < 0 || (ulong)integer > max) {
			*error = string::tformat("value %d does not fit in %d bits", integer, bit_width);
			return false;
		}
		return true;
	}
	if (integer < 0) {
		*error = string::tformat("negative value %d does not fit in 64 bits", integer);
		return false;
	}
	return true;
}

fn ulong? parse_uint_value(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	if (!s.len) {
		*error = "empty integer value";
		return PARSE_ERR~;
	}
	int base = 10;
	if (s.starts_with("0x") || s.starts_with("0X")) {
		base = 16;
		s = s[2..];
	}
	else if (s.starts_with("0b") || s.starts_with("0B")) {
		base = 2;
		s = s[2..];
	}
	if (!s.len) {
		*error = string::tformat("invalid integer value '%s'", raw);
		return PARSE_ERR~;
	}
	ulong? value = s.to_ulong(base);
	if (catch value) {
		*error = string::tformat("invalid integer value '%s'", raw);
		return PARSE_ERR~;
	}
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (value > max) {
			*error = string::tformat("value %d does not fit in %d bits", value, bit_width);
			return PARSE_ERR~;
		}
	}
	return value;
}

fn UIntRange? parse_uint_range(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	sz? dash = s.index_of_char('-');
	if (try dash) {
		ulong? left = parse_uint_value(s[..(usz)dash - 1], bit_width, error);
		if (catch left) return PARSE_ERR~;
		ulong? right = parse_uint_value(s[(usz)dash + 1..], bit_width, error);
		if (catch right) return PARSE_ERR~;
		if (left > right) {
			*error = string::tformat("range start %d is greater than range end %d", left, right);
			return PARSE_ERR~;
		}
		return { .first = left, .last = right };
	}
	ulong? v = parse_uint_value(s, bit_width, error);
	if (catch v) return PARSE_ERR~;
	return { .first = v, .last = v };
}

fn UIntRange[]? parse_uint_ranges(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		UIntRange? range = parse_uint_range(s, bit_width, error);
		if (catch range) return PARSE_ERR~;
		UIntRange[] one = mem::temp_array(UIntRange, 1);
		one[0] = range;
		return one;
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		*error = string::tformat("malformed range list '%s'", raw);
		return PARSE_ERR~;
	}
	String content = s.len >= 2 ? s[1..s.len - 2] : "";
	if (!content.trim().len) {
		*error = "empty range list";
		return PARSE_ERR~;
	}
	List{UIntRange} ranges;
	ranges.tinit();
	usz start = 0;
	usz index = 0;
	while (start <= content.len) {
		sz? comma = content.index_of_char_from(',', (sz)start);
		String item;
		if (catch comma) {
			item = content[start..].trim();
		}
		else {
			item = (usz)comma > start ? content[start..(usz)comma - 1].trim() : "";
		}
		if (!item.len) {
			*error = string::tformat("empty range at index %d", index);
			return PARSE_ERR~;
		}
		String item_err = "";
		UIntRange? range = parse_uint_range(item, bit_width, &item_err);
		if (catch range) {
			*error = string::tformat("invalid range at index %d: %s", index, item_err);
			return PARSE_ERR~;
		}
		ranges.push(range);
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return ranges.to_tarray();
}

fn int? parse_prefix(String s, int max_prefix, String* error) {
	String t = s.trim();
	if (!t.len) {
		*error = "empty CIDR mask";
		return PARSE_ERR~;
	}
	int? prefix = t.to_int();
	if (catch prefix) {
		*error = string::tformat("invalid CIDR mask '%s'", t);
		return PARSE_ERR~;
	}
	if (prefix < 0 || prefix > max_prefix) {
		*error = string::tformat("CIDR mask %d out of range [0,%d]", prefix, max_prefix);
		return PARSE_ERR~;
	}
	return prefix;
}

fn uint ipv4_to_u32(IPv4 ip) {
	return ((uint)ip.bytes[0] << 24) | ((uint)ip.bytes[1] << 16) | ((uint)ip.bytes[2] << 8) | (uint)ip.bytes[3];
}

fn IPv4 ipv4_from_u32(uint v) {
	char[4] bytes = { (char)(v >> 24), (char)((v >> 16) & 0xff), (char)((v >> 8) & 0xff), (char)(v & 0xff) };
	return value::ipv4_from_bytes(bytes);
}

fn IPv4Range? parse_ipv4_range(String raw, String* error) {
	String s = raw.trim();
	sz? slash = s.index_of_char('/');
	if (try slash) {
		String ip_part = s[..(usz)slash - 1];
		IPv4? ip = value::ipv4_parse(ip_part);
		if (catch ip) {
			*error = string::tformat("invalid ipv4 address '%s'", ip_part);
			return PARSE_ERR~;
		}
		int? prefix = parse_prefix(s[(usz)slash + 1..], 32, error);
		if (catch prefix) return PARSE_ERR~;
		uint mask = prefix == 0 ? 0 : ~(uint)0 << (32 - prefix);
		uint base = ipv4_to_u32(ip);
		return { .first = ipv4_from_u32(base & mask), .last = ipv4_from_u32(base | ~mask) };
	}
	sz? dash = s.index_of_char('-');
	if (try dash) {
		String left_str = s[..(usz)dash - 1].trim();
		String right_str = s[(usz)dash + 1..].trim();
		IPv4? left = value::ipv4_parse(left_str);
		if (catch left) {
			*error = string::tformat("invalid ipv4 address '%s'", left_str);
			return PARSE_ERR~;
		}
		IPv4? right = value::ipv4_parse(right_str);
		if (catch right) {
			*error = string::tformat("invalid ipv4 address '%s'", right_str);
			return PARSE_ERR~;
		}
		return { .first = left, .last = right };
	}
	IPv4? ip = value::ipv4_parse(s);
	if (catch ip) {
		*error = string::tformat("invalid ipv4 address '%s'", s);
		return PARSE_ERR~;
	}
	return { .first = ip, .last = ip };
}

fn IPv6Range? parse_ipv6_range(String raw, String* error) {
	String s = raw.trim();
	sz? slash = s.index_of_char('/');
	if (try slash) {
		String ip_part = s[..(usz)slash - 1];
		IPv6? ip = value::ipv6_parse(ip_part);
		if (catch ip) {
			*error = string::tformat("invalid ipv6 address '%s'", ip_part);
			return PARSE_ERR~;
		}
		int? prefix = parse_prefix(s[(usz)slash + 1..], 128, error);
		if (catch prefix) return PARSE_ERR~;
		char[16] first = ip.bytes;
		char[16] last = ip.bytes;
		for (int bit = prefix; bit < 128; bit++) {
			usz byte = (usz)(bit / 8);
			char mask = (char)(1u << (7 - bit % 8));
			first[byte] = (char)(first[byte] & ~mask);
			last[byte] = (char)(last[byte] | mask);
		}
		return { .first = value::ipv6_from_bytes(first), .last = value::ipv6_from_bytes(last) };
	}
	sz? dash = s.index_of_char('-');
	if (try dash) {
		String left_str = s[..(usz)dash - 1].trim();
		String right_str = s[(usz)dash + 1..].trim();
		IPv6? left = value::ipv6_parse(left_str);
		if (catch left) {
			*error = string::tformat("invalid ipv6 address '%s'", left_str);
			return PARSE_ERR~;
		}
		IPv6? right = value::ipv6_parse(right_str);
		if (catch right) {
			*error = string::tformat("invalid ipv6 address '%s'", right_str);
			return PARSE_ERR~;
		}
		return { .first = left, .last = right };
	}
	IPv6? ip = value::ipv6_parse(s);
	if (catch ip) {
		*error = string::tformat("invalid ipv6 address '%s'", s);
		return PARSE_ERR~;
	}
	return { .first = ip, .last = ip };
}

fn IPv4Range[]? parse_ipv4_ranges(String raw, String* error) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		IPv4Range? range = parse_ipv4_range(s, error);
		if (catch range) return PARSE_ERR~;
		IPv4Range[] one = mem::temp_array(IPv4Range, 1);
		one[0] = range;
		return one;
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		*error = string::tformat("malformed range list '%s'", raw);
		return PARSE_ERR~;
	}
	String content = s.len >= 2 ? s[1..s.len - 2] : "";
	if (!content.trim().len) {
		*error = "empty range list";
		return PARSE_ERR~;
	}
	List{IPv4Range} ranges;
	ranges.tinit();
	usz start = 0;
	usz index = 0;
	while (start <= content.len) {
		sz? comma = content.index_of_char_from(',', (sz)start);
		String item;
		if (catch comma) {
			item = content[start..].trim();
		}
		else {
			item = (usz)comma > start ? content[start..(usz)comma - 1].trim() : "";
		}
		if (!item.len) {
			*error = string::tformat("empty range at index %d", index);
			return PARSE_ERR~;
		}
		String item_err = "";
		IPv4Range? range = parse_ipv4_range(item, &item_err);
		if (catch range) {
			*error = string::tformat("invalid range at index %d: %s", index, item_err);
			return PARSE_ERR~;
		}
		ranges.push(range);
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return ranges.to_tarray();
}

fn IPv6Range[]? parse_ipv6_ranges(String raw, String* error) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		IPv6Range? range = parse_ipv6_range(s, error);
		if (catch range) return PARSE_ERR~;
		IPv6Range[] one = mem::temp_array(IPv6Range, 1);
		one[0] = range;
		return one;
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		*error = string::tformat("malformed range list '%s'", raw);
		return PARSE_ERR~;
	}
	String content = s.len >= 2 ? s[1..s.len - 2] : "";
	if (!content.trim().len) {
		*error = "empty range list";
		return PARSE_ERR~;
	}
	List{IPv6Range} ranges;
	ranges.tinit();
	usz start = 0;
	usz index = 0;
	while (start <= content.len) {
		sz? comma = content.index_of_char_from(',', (sz)start);
		String item;
		if (catch comma) {
			item = content[start..].trim();
		}
		else {
			item = (usz)comma > start ? content[start..(usz)comma - 1].trim() : "";
		}
		if (!item.len) {
			*error = string::tformat("empty range at index %d", index);
			return PARSE_ERR~;
		}
		String item_err = "";
		IPv6Range? range = parse_ipv6_range(item, &item_err);
		if (catch range) {
			*error = string::tformat("invalid range at index %d: %s", index, item_err);
			return PARSE_ERR~;
		}
		ranges.push(range);
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return ranges.to_tarray();
}
