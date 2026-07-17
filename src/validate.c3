module flowforge::validate;
import flowforge::ast;
import std::net;
import std::collections::list;

fn int hex_val(char c) {
	if (c.is_digit()) return (int)(c - '0');
	char lower = c.to_lower();
	if (lower >= 'a' && lower <= 'f') return (int)(lower - 'a' + 10);
	return -1;
}

fn bool parse_mac(String s) {
	if (s.len != 17) return false;
	for (usz i = 0; i < 6; i++) {
		usz base = i * 3;
		if (hex_val(s[base]) < 0 || hex_val(s[base + 1]) < 0) return false;
		if (i < 5 && s[base + 2] != ':') return false;
	}
	return true;
}

fn bool validate_mac(String s, String* err) {
	if (parse_mac(s)) return true;
	*err = string::tformat("invalid mac address '%s'", s);
	return false;
}

fn bool validate_ipv4(String s, String* err) {
	if (catch net::ipv4_from_str(s)) return true;
	*err = string::tformat("invalid ipv4 address '%s'", s);
	return false;
}

fn bool validate_ipv6(String s, String* err) {
	if (catch net::ipv6_from_str(s)) return true;
	*err = string::tformat("invalid ipv6 address '%s'", s);
	return false;
}

fn bool parse_ipv4_range(String raw, String* error) {
	String s = raw.trim();
	if (s.contains("/")) {
		sz? slash = s.index_of_char('/');
		if (catch slash) return false;
		String ip_part = (usz)slash > 0 ? s[..(usz)slash - 1].trim() : "";
		String mask_part = s[(usz)slash + 1..].trim();
		if (catch net::ipv4_from_str(ip_part)) {
			*error = string::tformat("invalid ipv4 address '%s'", ip_part);
			return false;
		}
		int? prefix = mask_part.to_int();
		if (catch prefix) {
			*error = string::tformat("invalid CIDR mask '%s'", mask_part);
			return false;
		}
		if (prefix < 0 || prefix > 32) {
			*error = string::tformat("invalid CIDR mask '%s'", mask_part);
			return false;
		}
		return true;
	}
	if (s.contains("-")) {
		sz? dash = s.index_of_char('-');
		if (catch dash) return false;
		String left = (usz)dash > 0 ? s[..(usz)dash - 1].trim() : "";
		String right = s[(usz)dash + 1..].trim();
		if (catch net::ipv4_from_str(left)) {
			*error = string::tformat("invalid ipv4 address '%s'", left);
			return false;
		}
		if (catch net::ipv4_from_str(right)) {
			*error = string::tformat("invalid ipv4 address '%s'", right);
			return false;
		}
		return true;
	}
	if (catch net::ipv4_from_str(s)) {
		*error = string::tformat("invalid ipv4 address '%s'", s);
		return false;
	}
	return true;
}

fn bool validate_ipv4_range(String s, String* err) {
	if (parse_ipv4_range(s, err)) return true;
	if (!err.len) *err = string::tformat("invalid ipv4 range '%s'", s);
	return false;
}

fn bool validate_ipv4_ranges(String s, String* err) {
	String raw = s.trim();
	if (raw.len && raw[0] == '[') {
		if (raw.len < 2 || raw[^1] != ']') {
			*err = string::tformat("malformed range list '%s'", s);
			return false;
		}
		String content = raw[1..raw.len - 2].trim();
		if (!content.len) {
			*err = "empty range list";
			return false;
		}
		usz start = 0;
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
				*err = string::tformat("empty range in list '%s'", s);
				return false;
			}
			if (!validate_ipv4_range(item, err)) return false;
			if (catch comma) break;
			start = (usz)comma + 1;
		}
		return true;
	}
	return validate_ipv4_range(s, err);
}

fn bool validate_ipv6_range(String s, String* err) {
	String raw = s.trim();
	if (raw.contains("-")) {
		sz? dash = raw.index_of_char('-');
		if (catch dash) return false;
		String left = (usz)dash > 0 ? raw[..(usz)dash - 1].trim() : "";
		String right = raw[(usz)dash + 1..].trim();
		if (catch net::ipv6_from_str(left)) {
			*err = string::tformat("invalid ipv6 address '%s'", left);
			return false;
		}
		if (catch net::ipv6_from_str(right)) {
			*err = string::tformat("invalid ipv6 address '%s'", right);
			return false;
		}
		return true;
	}
	if (catch net::ipv6_from_str(raw)) {
		return validate_ipv6(raw, err);
	}
	return true;
}

fn bool validate_ipv6_ranges(String s, String* err) => validate_ipv6_range(s, err);

faultdef UNKNOWN_TYPE;

fn usz? bit_width_for_type(String type_name) {
	if (type_name == "mac") return 48;
	if (type_name == "ipv4" || type_name == "ipv4_range" || type_name == "ipv4_ranges") return 32;
	if (type_name == "ipv6" || type_name == "ipv6_range" || type_name == "ipv6_ranges") return 128;
	if (type_name.ends_with("_ranges") && type_name.len > 8 && type_name[0] == 'b') {
		ulong? width = type_name[1..type_name.len - 8].to_ulong();
		if (catch width) return UNKNOWN_TYPE~;
		if (width < 1 || width > 64) return UNKNOWN_TYPE~;
		return (usz)width;
	}
	if (type_name.len > 1 && type_name[0] == 'b') {
		ulong? width = type_name[1..].to_ulong();
		if (catch width) return UNKNOWN_TYPE~;
		if (width < 1 || width > 64) return UNKNOWN_TYPE~;
		return (usz)width;
	}
	return UNKNOWN_TYPE~;
}

fn bool validate_bit_value(long integer, usz bit_width, String* err) {
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (integer < 0 || (ulong)integer > max) {
			*err = string::tformat("value %d does not fit in %d bits", integer, bit_width);
			return false;
		}
		return true;
	}
	if (integer < 0) {
		*err = string::tformat("negative value %d does not fit in 64 bits", integer);
		return false;
	}
	return true;
}

fn bool parse_uint_value(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	if (!s.len) {
		*error = "empty integer value";
		return false;
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
	ulong? value = s.to_ulong(base);
	if (catch value) {
		*error = string::tformat("invalid integer value '%s'", raw);
		return false;
	}
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (value > max) {
			*error = string::tformat("value %d does not fit in %d bits", value, bit_width);
			return false;
		}
	}
	return true;
}

fn bool validate_bit_range_value(String type_name, ScalarValue value, String* err) {
	usz bit_width = bit_width_for_type(type_name)!!;
	if (value.kind == ScalarKind.INTEGER) {
		return validate_bit_value(value.int_val, bit_width, err);
	}
	if (value.kind != ScalarKind.STRING) {
		*err = "expected integer or string value";
		return false;
	}

	String raw = value.string_val.trim();
	if (raw.len && raw[0] == '[') {
		if (raw.len < 2 || raw[^1] != ']') {
			*err = string::tformat("malformed range list '%s'", raw);
			return false;
		}
		String content = raw[1..raw.len - 2].trim();
		if (!content.len) {
			*err = "empty range list";
			return false;
		}
		usz start = 0;
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
				*err = "empty range in list";
				return false;
			}
			if (item.contains("-")) {
				sz? dash = item.index_of_char('-');
				if (catch dash) return false;
				if (!parse_uint_value((usz)dash > 0 ? item[..(usz)dash - 1].trim() : "", bit_width, err)) return false;
				if (!parse_uint_value(item[(usz)dash + 1..].trim(), bit_width, err)) return false;
			}
			else if (!parse_uint_value(item, bit_width, err)) {
				return false;
			}
			if (catch comma) break;
			start = (usz)comma + 1;
		}
		return true;
	}
	if (raw.contains("-")) {
		sz? dash = raw.index_of_char('-');
		if (catch dash) return false;
		if (!parse_uint_value((usz)dash > 0 ? raw[..(usz)dash - 1].trim() : "", bit_width, err)) return false;
		if (!parse_uint_value(raw[(usz)dash + 1..].trim(), bit_width, err)) return false;
		return true;
	}
	return parse_uint_value(raw, bit_width, err);
}

fn bool validate_scalar_type(String type_name, ScalarValue value, String* err) {
	switch (type_name) {
		case "mac":
			if (value.kind != ScalarKind.STRING) {
				*err = "mac address must be a string value";
				return false;
			}
			return validate_mac(value.string_val, err);
		case "ipv4":
			if (value.kind != ScalarKind.STRING) {
				*err = "ipv4 address must be a string value";
				return false;
			}
			return validate_ipv4(value.string_val, err);
		case "ipv6":
			if (value.kind != ScalarKind.STRING) {
				*err = "ipv6 address must be a string value";
				return false;
			}
			return validate_ipv6(value.string_val, err);
		case "ipv4_range":
			if (value.kind != ScalarKind.STRING) {
				*err = "ipv4 range must be a string value";
				return false;
			}
			return validate_ipv4_range(value.string_val, err);
		case "ipv6_range":
			if (value.kind != ScalarKind.STRING) {
				*err = "ipv6 range must be a string value";
				return false;
			}
			return validate_ipv6_range(value.string_val, err);
		case "ipv4_ranges":
			if (value.kind != ScalarKind.STRING) {
				*err = "ipv4 ranges must be a string value";
				return false;
			}
			return validate_ipv4_ranges(value.string_val, err);
		case "ipv6_ranges":
			if (value.kind != ScalarKind.STRING) {
				*err = "ipv6 ranges must be a string value";
				return false;
			}
			return validate_ipv6_ranges(value.string_val, err);
		default:
			if (type_name.len > 1 && type_name[0] == 'b') {
				if (catch bit_width_for_type(type_name)) {
					*err = string::tformat("unsupported type '%s'", type_name);
					return false;
				}
				return validate_bit_range_value(type_name, value, err);
			}
			*err = string::tformat("unsupported type '%s'", type_name);
			return false;
	}
}
