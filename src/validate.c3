module flowforge::validate;
import flowforge::ast;
import flowforge::cvalue;
import flowforge::value;
import std::collections::result;
import std::net;

fn Result{bool, String} validate_mac(String s) {
	MacAddr? mac = value::mac_parse(s);
	if (catch mac) return result::err(string::tformat("invalid mac address '%s'", s));
	return result::ok(true);
}

fn Result{bool, String} validate_ipv4(String s) {
	if (catch net::ipv4_from_str(s)) {
		return result::err(string::tformat("invalid ipv4 address '%s'", s));
	}
	return result::ok(true);
}

fn Result{bool, String} validate_ipv6(String s) {
	if (catch net::ipv6_from_str(s)) {
		return result::err(string::tformat("invalid ipv6 address '%s'", s));
	}
	return result::ok(true);
}

fn Result{bool, String} parse_prefix(String s, int max_prefix) {
	Result{int, String} prefix = cvalue::parse_prefix(s, max_prefix);
	if (!prefix.is_ok) return result::err(prefix.error);
	return result::ok(true);
}

fn Result{bool, String} parse_ipv4_range(String raw) {
	Result{IPv4Range, String} range = cvalue::parse_ipv4_range(raw);
	if (!range.is_ok) return result::err(range.error);
	return result::ok(true);
}

fn Result{bool, String} validate_ipv4_range(String s) => parse_ipv4_range(s);

fn Result{bool, String} validate_ipv4_ranges(String s) {
	Result{IPv4Range[], String} ranges = cvalue::parse_ipv4_ranges(s);
	if (!ranges.is_ok) return result::err(ranges.error);
	return result::ok(true);
}

fn Result{bool, String} parse_ipv6_range(String raw) {
	Result{IPv6Range, String} range = cvalue::parse_ipv6_range(raw);
	if (!range.is_ok) return result::err(range.error);
	return result::ok(true);
}

fn Result{bool, String} validate_ipv6_range(String s) => parse_ipv6_range(s);

fn Result{bool, String} validate_ipv6_ranges(String s) {
	Result{IPv6Range[], String} ranges = cvalue::parse_ipv6_ranges(s);
	if (!ranges.is_ok) return result::err(ranges.error);
	return result::ok(true);
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

fn Result{bool, String} validate_bit_range_value(usz bit_width, ScalarValue value) {
	if (value.kind == ScalarKind.INTEGER) {
		return cvalue::validate_bit_value(value.int_val, bit_width);
	}
	if (value.kind != ScalarKind.STRING) {
		return result::err("expected integer or string value");
	}
	String raw = value.string_val.trim();
	if ((raw.len && raw[0] == '[') || raw.ends_with("]") || raw.contains("-")) {
		Result{UIntRange[], String} ranges = cvalue::parse_uint_ranges(raw, bit_width);
		if (!ranges.is_ok) return result::err(ranges.error);
		return result::ok(true);
	}
	Result{ulong, String} parsed = cvalue::parse_uint_value(raw, bit_width);
	if (!parsed.is_ok) return result::err(parsed.error);
	return result::ok(true);
}

fn Result{bool, String} validate_plain_bit_value(usz bit_width, ScalarValue value) {
	if (value.kind != ScalarKind.INTEGER) {
		return result::err("expected integer value");
	}
	return cvalue::validate_bit_value(value.int_val, bit_width);
}

fn Result{bool, String} validate_scalar_type(String type_name, ScalarValue value) {
	switch (type_name) {
		case "mac":
			if (value.kind != ScalarKind.STRING) {
				return result::err("mac address must be a string value");
			}
			return validate_mac(value.string_val);
		case "ipv4":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv4 address must be a string value");
			}
			return validate_ipv4(value.string_val);
		case "ipv6":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv6 address must be a string value");
			}
			return validate_ipv6(value.string_val);
		case "ipv4_range":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv4 range must be a string value");
			}
			return validate_ipv4_range(value.string_val);
		case "ipv6_range":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv6 range must be a string value");
			}
			return validate_ipv6_range(value.string_val);
		case "ipv4_ranges":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv4 ranges must be a string value");
			}
			return validate_ipv4_ranges(value.string_val);
		case "ipv6_ranges":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv6 ranges must be a string value");
			}
			return validate_ipv6_ranges(value.string_val);
		default:
			usz? width = bit_width_for_type(type_name);
			if (catch width) {
				return result::err(string::tformat("unsupported type '%s'", type_name));
			}
			if (is_bit_ranges_type(type_name)) {
				return validate_bit_range_value(width, value);
			}
			return validate_plain_bit_value(width, value);
	}
}
