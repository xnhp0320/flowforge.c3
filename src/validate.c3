module flowforge::validate;
import flowforge::ast;
import flowforge::cvalue;
import flowforge::value;
import std::collections::result;
import std::net;

faultdef UNKNOWN_TYPE;

fn bool is_bit_ranges_type(String type_name) {
	return type_name.ends_with("_ranges") && type_name.len > 8 && type_name[0] == 'b';
}

fn usz? bit_width_for_type(String type_name) {
	if (is_bit_ranges_type(type_name)) {
		ulong? width = type_name[1..^8].to_ulong();
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
			if (catch value::mac_parse(value.string_val)) {
				return result::err(string::tformat("invalid mac address '%s'", value.string_val));
			}
			return result::ok(true);
		case "ipv4":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv4 address must be a string value");
			}
			if (catch net::ipv4_from_str(value.string_val)) {
				return result::err(string::tformat("invalid ipv4 address '%s'", value.string_val));
			}
			return result::ok(true);
		case "ipv6":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv6 address must be a string value");
			}
			if (catch net::ipv6_from_str(value.string_val)) {
				return result::err(string::tformat("invalid ipv6 address '%s'", value.string_val));
			}
			return result::ok(true);
		case "ipv4_range":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv4 range must be a string value");
			}
			Result{IPv4Range, String} range = cvalue::parse_ipv4_range(value.string_val);
			if (!range.is_ok) return result::err(range.error);
			return result::ok(true);
		case "ipv6_range":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv6 range must be a string value");
			}
			Result{IPv6Range, String} range = cvalue::parse_ipv6_range(value.string_val);
			if (!range.is_ok) return result::err(range.error);
			return result::ok(true);
		case "ipv4_ranges":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv4 ranges must be a string value");
			}
			Result{IPv4Range[], String} ranges = cvalue::parse_ipv4_ranges(value.string_val);
			if (!ranges.is_ok) return result::err(ranges.error);
			return result::ok(true);
		case "ipv6_ranges":
			if (value.kind != ScalarKind.STRING) {
				return result::err("ipv6 ranges must be a string value");
			}
			Result{IPv6Range[], String} ranges = cvalue::parse_ipv6_ranges(value.string_val);
			if (!ranges.is_ok) return result::err(ranges.error);
			return result::ok(true);
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
