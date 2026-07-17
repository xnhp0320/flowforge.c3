module flowforge::validate;
import flowforge::ast;
import std::net;

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
	if (catch net::ipv4_from_str(s)) {
		*err = string::tformat("invalid ipv4 address '%s'", s);
		return false;
	}
	return true;
}

fn bool validate_ipv6(String s, String* err) {
	if (catch net::ipv6_from_str(s)) {
		*err = string::tformat("invalid ipv6 address '%s'", s);
		return false;
	}
	return true;
}

fn bool parse_prefix(String s, int max_prefix, String* error) {
	String mask = s.trim();
	if (!mask.len) {
		*error = "empty CIDR mask";
		return false;
	}
	int? prefix = mask.to_int();
	if (catch prefix) {
		*error = string::tformat("invalid CIDR mask '%s'", mask);
		return false;
	}
	if (prefix < 0 || prefix > max_prefix) {
		*error = string::tformat("CIDR mask %d out of range [0,%d]", prefix, max_prefix);
		return false;
	}
	return true;
}

fn bool parse_ipv4_range(String raw, String* error) {
	String s = raw.trim();
	if (s.contains("/")) {
		sz? slash = s.index_of_char('/');
		if (catch slash) return false;
		String ip_part = (usz)slash > 0 ? s[..(usz)slash - 1].trim() : "";
		String mask_part = s[(usz)slash + 1..].trim();
		if (!validate_ipv4(ip_part, error)) return false;
		return parse_prefix(mask_part, 32, error);
	}
	if (s.contains("-")) {
		sz? dash = s.index_of_char('-');
		if (catch dash) return false;
		String left = (usz)dash > 0 ? s[..(usz)dash - 1].trim() : "";
		String right = s[(usz)dash + 1..].trim();
		if (!validate_ipv4(left, error)) return false;
		return validate_ipv4(right, error);
	}
	return validate_ipv4(s, error);
}

fn bool validate_ipv4_range(String s, String* err) => parse_ipv4_range(s, err);

fn bool validate_ipv4_ranges(String s, String* err) {
	String raw = s.trim();
	if (!(raw.len && raw[0] == '[') && !raw.ends_with("]")) {
		return validate_ipv4_range(s, err);
	}
	if (!(raw.len && raw[0] == '[') || !raw.ends_with("]")) {
		*err = string::tformat("malformed range list '%s'", s);
		return false;
	}
	String content = raw.len >= 2 ? raw[1..raw.len - 2] : "";
	if (!content.trim().len) {
		*err = "empty range list";
		return false;
	}
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
			*err = string::tformat("empty range at index %d", index);
			return false;
		}
		String item_err = "";
		if (!parse_ipv4_range(item, &item_err)) {
			*err = string::tformat("invalid range at index %d: %s", index, item_err);
			return false;
		}
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return true;
}

fn bool parse_ipv6_range(String raw, String* error) {
	String s = raw.trim();
	if (s.contains("/")) {
		sz? slash = s.index_of_char('/');
		if (catch slash) return false;
		String ip_part = (usz)slash > 0 ? s[..(usz)slash - 1].trim() : "";
		String mask_part = s[(usz)slash + 1..].trim();
		if (!validate_ipv6(ip_part, error)) return false;
		return parse_prefix(mask_part, 128, error);
	}
	if (s.contains("-")) {
		sz? dash = s.index_of_char('-');
		if (catch dash) return false;
		String left = (usz)dash > 0 ? s[..(usz)dash - 1].trim() : "";
		String right = s[(usz)dash + 1..].trim();
		if (!validate_ipv6(left, error)) return false;
		return validate_ipv6(right, error);
	}
	return validate_ipv6(s, error);
}

fn bool validate_ipv6_range(String s, String* err) => parse_ipv6_range(s, err);

fn bool validate_ipv6_ranges(String s, String* err) {
	String raw = s.trim();
	if (!(raw.len && raw[0] == '[') && !raw.ends_with("]")) {
		return validate_ipv6_range(s, err);
	}
	if (!(raw.len && raw[0] == '[') || !raw.ends_with("]")) {
		*err = string::tformat("malformed range list '%s'", s);
		return false;
	}
	String content = raw.len >= 2 ? raw[1..raw.len - 2] : "";
	if (!content.trim().len) {
		*err = "empty range list";
		return false;
	}
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
			*err = string::tformat("empty range at index %d", index);
			return false;
		}
		String item_err = "";
		if (!parse_ipv6_range(item, &item_err)) {
			*err = string::tformat("invalid range at index %d: %s", index, item_err);
			return false;
		}
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return true;
}

faultdef UNKNOWN_TYPE;

fn bool is_bit_ranges_type(String type_name) {
	return type_name.ends_with("_ranges") && type_name.len > 8 && type_name[0] == 'b';
}

fn usz? bit_width_for_type(String type_name) {
	if (is_bit_ranges_type(type_name)) {
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

fn ulong? parse_uint_value(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	if (!s.len) {
		*error = "empty integer value";
		return PARSE_UINT~;
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
		return PARSE_UINT~;
	}
	ulong? value = s.to_ulong(base);
	if (catch value) {
		*error = string::tformat("invalid integer value '%s'", raw);
		return PARSE_UINT~;
	}
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (value > max) {
			*error = string::tformat("value %d does not fit in %d bits", value, bit_width);
			return PARSE_UINT~;
		}
	}
	return value;
}

faultdef PARSE_UINT;

fn bool parse_uint_range(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	if (s.contains("-")) {
		sz? dash = s.index_of_char('-');
		if (catch dash) return false;
		ulong? left = parse_uint_value((usz)dash > 0 ? s[..(usz)dash - 1].trim() : "", bit_width, error);
		if (catch left) return false;
		ulong? right = parse_uint_value(s[(usz)dash + 1..].trim(), bit_width, error);
		if (catch right) return false;
		if (left > right) {
			*error = string::tformat("range start %d is greater than range end %d", left, right);
			return false;
		}
		return true;
	}
	ulong? value = parse_uint_value(s, bit_width, error);
	if (catch value) return false;
	return true;
}

fn bool parse_uint_ranges(String raw, usz bit_width, String* error) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		return parse_uint_range(s, bit_width, error);
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		*error = string::tformat("malformed range list '%s'", raw);
		return false;
	}
	String content = s.len >= 2 ? s[1..s.len - 2] : "";
	if (!content.trim().len) {
		*error = "empty range list";
		return false;
	}
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
			return false;
		}
		String item_err = "";
		if (!parse_uint_range(item, bit_width, &item_err)) {
			*error = string::tformat("invalid range at index %d: %s", index, item_err);
			return false;
		}
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return true;
}

fn bool validate_bit_range_value(usz bit_width, ScalarValue value, String* err) {
	if (value.kind == ScalarKind.INTEGER) {
		return validate_bit_value(value.int_val, bit_width, err);
	}
	if (value.kind != ScalarKind.STRING) {
		*err = "expected integer or string value";
		return false;
	}
	String raw = value.string_val.trim();
	if ((raw.len && raw[0] == '[') || raw.ends_with("]") || raw.contains("-")) {
		return parse_uint_ranges(raw, bit_width, err);
	}
	ulong? parsed = parse_uint_value(raw, bit_width, err);
	if (catch parsed) return false;
	return true;
}

fn bool validate_plain_bit_value(usz bit_width, ScalarValue value, String* err) {
	if (value.kind != ScalarKind.INTEGER) {
		*err = "expected integer value";
		return false;
	}
	return validate_bit_value(value.int_val, bit_width, err);
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
			usz? width = bit_width_for_type(type_name);
			if (catch width) {
				*err = string::tformat("unsupported type '%s'", type_name);
				return false;
			}
			if (is_bit_ranges_type(type_name)) {
				return validate_bit_range_value(width, value, err);
			}
			return validate_plain_bit_value(width, value, err);
	}
}
