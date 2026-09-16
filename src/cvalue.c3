module flowforge::cvalue;
import flowforge::value;
import std::collections::list;
import std::collections::maybe;
import std::collections::result;

faultdef PARSE_ERR;

fn usz? bit_range_width_for_type_name(String type_name) {
	if (!(type_name.len && type_name[0] == 'b') || !type_name.ends_with("_ranges")) {
		return PARSE_ERR~;
	}
	String digits = type_name[1..^8];
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
		// Bound plain `bN` to 1..64 to match `bN_ranges` and the DSL
		// validator; wider widths cannot be represented by a `ulong` value.
		if (try width && width >= 1 && width <= 64) return (usz)width;
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

fn Result{bool, String} validate_bit_value(long integer, usz bit_width) {
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (integer < 0 || (ulong)integer > max) {
			return result::err(string::tformat("value %d does not fit in %d bits", integer, bit_width));
		}
		return result::ok(true);
	}
	if (integer < 0) {
		return result::err(string::tformat("negative value %d does not fit in 64 bits", integer));
	}
	return result::ok(true);
}

fn Result{ulong, String} parse_uint_value(String raw, usz bit_width) {
	String s = raw.trim();
	if (!s.len) return result::err("empty integer value");
	int base = 10;
	if (s.starts_with("0x") || s.starts_with("0X")) {
		base = 16;
		s = s[2..];
	}
	else if (s.starts_with("0b") || s.starts_with("0B")) {
		base = 2;
		s = s[2..];
	}
	if (!s.len) return result::err(string::tformat("invalid integer value '%s'", raw));
	ulong? value = s.to_ulong(base);
	if (catch value) return result::err(string::tformat("invalid integer value '%s'", raw));
	if (bit_width < 64) {
		ulong max = (1UL << bit_width) - 1;
		if (value > max) {
			return result::err(string::tformat("value %d does not fit in %d bits", value, bit_width));
		}
	}
	return result::ok(value);
}

struct RangeModifierAttribute {
	String name;
	Maybe{String} value;
}

struct ParsedRangeModifier {
	String range;
	RangeModifierAttribute[] attributes;
}

struct RangeModifierOptions {
	Maybe{ulong} step;
	bool random;
}

fn Result{ParsedRangeModifier, String} parse_range_modifier(String raw) {
	String s = raw.trim();
	sz? open = s.index_of_char('(');
	if (catch open) {
		if (s.contains(")")) return result::err(string::tformat("malformed range modifier in '%s'", raw));
		return result::ok({ .range = s });
	}
	if (!s.ends_with(")")) return result::err(string::tformat("malformed range modifier in '%s'", raw));
	String body = s[(usz)open + 1..^2].trim();
	if (body.contains("(") || body.contains(")")) {
		return result::err(string::tformat("malformed range modifier in '%s'", raw));
	}
	if (!body.len) return result::err(string::tformat("empty range modifier in '%s'", raw));
	List{RangeModifierAttribute} attributes;
	attributes.tinit();
	usz start = 0;
	while (start <= body.len) {
		sz? comma = body.index_of_char_from(',', (sz)start);
		String item;
		if (catch comma) {
			item = body[start..].trim();
		}
		else {
			item = body[start..(usz)comma - 1].trim();
		}
		if (!item.len) return result::err(string::tformat("empty range modifier attribute in '%s'", raw));
		sz? equals = item.index_of_char('=');
		if (catch equals) {
			attributes.push({ .name = item });
		}
		else {
			if (item[(usz)equals + 1..].contains("=")) {
				return result::err(string::tformat("malformed range modifier in '%s'", raw));
			}
			String name = item[..(usz)equals - 1].trim();
			String attr_value = item[(usz)equals + 1..].trim();
			if (!name.len) return result::err(string::tformat("malformed range modifier in '%s'", raw));
			RangeModifierAttribute attribute = { .name = name };
			attribute.value.set(attr_value);
			attributes.push(attribute);
		}
		if (catch comma) break;
		start = (usz)comma + 1;
	}
	String range = s[..(usz)open - 1].trim();
	if (!range.len) return result::err("range modifier requires an explicit start-end range");
	return result::ok({ .range = range, .attributes = attributes.to_tarray() });
}

fn Result{RangeModifierOptions, String} parse_range_modifier_options(RangeModifierAttribute[] attributes) {
	RangeModifierOptions options;
	foreach (attribute : attributes) {
		if (attribute.name == "rand") {
			if (options.random) return result::err("duplicate range modifier 'rand'");
			if (attribute.value.has_value) return result::err("range rand modifier does not accept a value");
			if (options.step.has_value) return result::err("range modifiers 'step' and 'rand' are mutually exclusive");
			options.random = true;
			continue;
		}
		if (attribute.name != "step") return result::err(string::tformat("unknown range modifier '%s'", attribute.name));
		if (options.step.has_value) return result::err("duplicate range modifier attribute 'step'");
		if (options.random) return result::err("range modifiers 'step' and 'rand' are mutually exclusive");
		if (!attribute.value.has_value || !attribute.value.value.len) {
			return result::err("range step must be a decimal positive integer");
		}
		String raw_step = attribute.value.value;
		foreach (c : raw_step) {
			if (!c.is_digit()) return result::err("range step must be a decimal positive integer");
		}
		ulong? step = raw_step.to_ulong();
		if (catch step) return result::err("range step is out of range");
		if (step == 0) return result::err("range step must be greater than zero");
		options.step.set(step);
	}
	return result::ok(options);
}

fn Result{UIntRange, String} parse_uint_range(String raw, usz bit_width) {
	Result{ParsedRangeModifier, String} parsed = parse_range_modifier(raw);
	if (!parsed.is_ok) return result::err(parsed.error);
	Result{RangeModifierOptions, String} options = parse_range_modifier_options(parsed.value.attributes);
	if (!options.is_ok) return result::err(options.error);
	String s = parsed.value.range;
	sz? dash = s.index_of_char('-');
	if (try dash) {
		Result{ulong, String} left = parse_uint_value(s[..(usz)dash - 1], bit_width);
		if (!left.is_ok) return result::err(left.error);
		Result{ulong, String} right = parse_uint_value(s[(usz)dash + 1..], bit_width);
		if (!right.is_ok) return result::err(right.error);
		if (left.value > right.value) {
			return result::err(string::tformat("range start %d is greater than range end %d", left.value, right.value));
		}
		return result::ok({
			.first = left.value,
			.last = right.value,
			.step = options.value.step,
			.random = options.value.random,
		});
	}
	if (parsed.value.attributes.len) return result::err("range step requires an explicit start-end range");
	Result{ulong, String} v = parse_uint_value(s, bit_width);
	if (!v.is_ok) return result::err(v.error);
	return result::ok({ .first = v.value, .last = v.value });
}

fn sz? find_range_list_comma(String content, usz start) {
	int modifier_depth = 0;
	for (usz index = start; index < content.len; index++) {
		if (content[index] == '(') {
			modifier_depth++;
		}
		else if (content[index] == ')' && modifier_depth > 0) {
			modifier_depth--;
		}
		else if (content[index] == ',' && modifier_depth == 0) {
			return (sz)index;
		}
	}
	return PARSE_ERR~;
}

fn Result{UIntRange[], String} parse_uint_ranges(String raw, usz bit_width) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		Result{UIntRange, String} range = parse_uint_range(s, bit_width);
		if (!range.is_ok) return result::err(range.error);
		UIntRange[] one = mem::temp_array(UIntRange, 1);
		one[0] = range.value;
		return result::ok(one);
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		return result::err(string::tformat("malformed range list '%s'", raw));
	}
	String content = s.len >= 2 ? s[1..^2] : "";
	if (!content.trim().len) return result::err("empty range list");
	List{UIntRange} ranges;
	ranges.tinit();
	usz start = 0;
	usz index = 0;
	while (start <= content.len) {
		sz? comma = find_range_list_comma(content, start);
		String item;
		if (catch comma) {
			item = content[start..].trim();
		}
		else {
			item = (usz)comma > start ? content[start..(usz)comma - 1].trim() : "";
		}
		if (!item.len) {
			return result::err(string::tformat("empty range at index %d", index));
		}
		Result{UIntRange, String} range = parse_uint_range(item, bit_width);
		if (!range.is_ok) {
			return result::err(string::tformat("invalid range at index %d: %s", index, range.error));
		}
		ranges.push(range.value);
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return result::ok(ranges.to_tarray());
}

fn Result{int, String} parse_prefix(String s, int max_prefix) {
	String t = s.trim();
	if (!t.len) return result::err("empty CIDR mask");
	int? prefix = t.to_int();
	if (catch prefix) return result::err(string::tformat("invalid CIDR mask '%s'", t));
	if (prefix < 0 || prefix > max_prefix) {
		return result::err(string::tformat("CIDR mask %d out of range [0,%d]", prefix, max_prefix));
	}
	return result::ok(prefix);
}

fn uint ipv4_to_u32(IPv4 ip) {
	return ((uint)ip.bytes[0] << 24) | ((uint)ip.bytes[1] << 16) | ((uint)ip.bytes[2] << 8) | (uint)ip.bytes[3];
}

fn uint128 ipv6_to_u128(IPv6 ip) {
	uint128 value = 0;
	foreach (byte : ip.bytes) value = (value << 8) | (uint128)byte;
	return value;
}

fn IPv6 ipv6_from_u128(uint128 value) {
	char[16] bytes;
	for (usz index = 16; index > 0; index--) {
		bytes[index - 1] = (char)(value & 0xff);
		value >>= 8;
	}
	return value::ipv6_from_bytes(bytes);
}

fn IPv4 ipv4_from_u32(uint v) {
	char[4] bytes = { (char)(v >> 24), (char)((v >> 16) & 0xff), (char)((v >> 8) & 0xff), (char)(v & 0xff) };
	return value::ipv4_from_bytes(bytes);
}

fn Result{IPv4Range, String} parse_ipv4_range(String raw) {
	Result{ParsedRangeModifier, String} parsed = parse_range_modifier(raw);
	if (!parsed.is_ok) return result::err(parsed.error);
	Result{RangeModifierOptions, String} options = parse_range_modifier_options(parsed.value.attributes);
	if (!options.is_ok) return result::err(options.error);
	String s = parsed.value.range;
	sz? slash = s.index_of_char('/');
	if (try slash) {
		if (parsed.value.attributes.len) return result::err("range modifiers are not supported for CIDR ranges");
		String ip_part = s[..(usz)slash - 1];
		IPv4? ip = value::ipv4_parse(ip_part);
		if (catch ip) return result::err(string::tformat("invalid ipv4 address '%s'", ip_part));
		Result{int, String} prefix = parse_prefix(s[(usz)slash + 1..], 32);
		if (!prefix.is_ok) return result::err(prefix.error);
		uint mask = prefix.value == 0 ? 0 : ~(uint)0 << (32 - prefix.value);
		uint base = ipv4_to_u32(ip);
		return result::ok({ .first = ipv4_from_u32(base & mask), .last = ipv4_from_u32(base | ~mask) });
	}
	sz? dash = s.index_of_char('-');
	if (try dash) {
		String left_str = s[..(usz)dash - 1].trim();
		String right_str = s[(usz)dash + 1..].trim();
		IPv4? left = value::ipv4_parse(left_str);
		if (catch left) return result::err(string::tformat("invalid ipv4 address '%s'", left_str));
		IPv4? right = value::ipv4_parse(right_str);
		if (catch right) return result::err(string::tformat("invalid ipv4 address '%s'", right_str));
		if (ipv4_to_u32(left) > ipv4_to_u32(right)) return result::err("ipv4 range start is greater than range end");
		return result::ok({
			.first = left,
			.last = right,
			.step = options.value.step,
			.random = options.value.random,
		});
	}
	if (parsed.value.attributes.len) return result::err("range modifiers require an explicit start-end range");
	IPv4? ip = value::ipv4_parse(s);
	if (catch ip) return result::err(string::tformat("invalid ipv4 address '%s'", s));
	return result::ok({ .first = ip, .last = ip });
}

fn Result{IPv6Range, String} parse_ipv6_range(String raw) {
	Result{ParsedRangeModifier, String} parsed = parse_range_modifier(raw);
	if (!parsed.is_ok) return result::err(parsed.error);
	Result{RangeModifierOptions, String} options = parse_range_modifier_options(parsed.value.attributes);
	if (!options.is_ok) return result::err(options.error);
	String s = parsed.value.range;
	sz? slash = s.index_of_char('/');
	if (try slash) {
		if (parsed.value.attributes.len) return result::err("range modifiers are not supported for CIDR ranges");
		String ip_part = s[..(usz)slash - 1];
		IPv6? ip = value::ipv6_parse(ip_part);
		if (catch ip) return result::err(string::tformat("invalid ipv6 address '%s'", ip_part));
		Result{int, String} prefix = parse_prefix(s[(usz)slash + 1..], 128);
		if (!prefix.is_ok) return result::err(prefix.error);
		char[16] first = ip.bytes;
		char[16] last = ip.bytes;
		for (int bit = prefix.value; bit < 128; bit++) {
			usz byte = (usz)(bit / 8);
			char mask = (char)(1u << (7 - bit % 8));
			first[byte] = (char)(first[byte] & ~mask);
			last[byte] = (char)(last[byte] | mask);
		}
		return result::ok({ .first = value::ipv6_from_bytes(first), .last = value::ipv6_from_bytes(last) });
	}
	sz? dash = s.index_of_char('-');
	if (try dash) {
		String left_str = s[..(usz)dash - 1].trim();
		String right_str = s[(usz)dash + 1..].trim();
		IPv6? left = value::ipv6_parse(left_str);
		if (catch left) return result::err(string::tformat("invalid ipv6 address '%s'", left_str));
		IPv6? right = value::ipv6_parse(right_str);
		if (catch right) return result::err(string::tformat("invalid ipv6 address '%s'", right_str));
		if (ipv6_to_u128(left) > ipv6_to_u128(right)) return result::err("ipv6 range start is greater than range end");
		return result::ok({
			.first = left,
			.last = right,
			.step = options.value.step,
			.random = options.value.random,
		});
	}
	if (parsed.value.attributes.len) return result::err("range modifiers require an explicit start-end range");
	IPv6? ip = value::ipv6_parse(s);
	if (catch ip) return result::err(string::tformat("invalid ipv6 address '%s'", s));
	return result::ok({ .first = ip, .last = ip });
}

fn Result{IPv4Range[], String} parse_ipv4_ranges(String raw) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		Result{IPv4Range, String} range = parse_ipv4_range(s);
		if (!range.is_ok) return result::err(range.error);
		IPv4Range[] one = mem::temp_array(IPv4Range, 1);
		one[0] = range.value;
		return result::ok(one);
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		return result::err(string::tformat("malformed range list '%s'", raw));
	}
	String content = s.len >= 2 ? s[1..^2] : "";
	if (!content.trim().len) return result::err("empty range list");
	List{IPv4Range} ranges;
	ranges.tinit();
	usz start = 0;
	usz index = 0;
	while (start <= content.len) {
		sz? comma = find_range_list_comma(content, start);
		String item;
		if (catch comma) {
			item = content[start..].trim();
		}
		else {
			item = (usz)comma > start ? content[start..(usz)comma - 1].trim() : "";
		}
		if (!item.len) {
			return result::err(string::tformat("empty range at index %d", index));
		}
		Result{IPv4Range, String} range = parse_ipv4_range(item);
		if (!range.is_ok) {
			return result::err(string::tformat("invalid range at index %d: %s", index, range.error));
		}
		ranges.push(range.value);
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return result::ok(ranges.to_tarray());
}

fn Result{IPv6Range[], String} parse_ipv6_ranges(String raw) {
	String s = raw.trim();
	if (!(s.len && s[0] == '[') && !s.ends_with("]")) {
		Result{IPv6Range, String} range = parse_ipv6_range(s);
		if (!range.is_ok) return result::err(range.error);
		IPv6Range[] one = mem::temp_array(IPv6Range, 1);
		one[0] = range.value;
		return result::ok(one);
	}
	if (!(s.len && s[0] == '[') || !s.ends_with("]")) {
		return result::err(string::tformat("malformed range list '%s'", raw));
	}
	String content = s.len >= 2 ? s[1..^2] : "";
	if (!content.trim().len) return result::err("empty range list");
	List{IPv6Range} ranges;
	ranges.tinit();
	usz start = 0;
	usz index = 0;
	while (start <= content.len) {
		sz? comma = find_range_list_comma(content, start);
		String item;
		if (catch comma) {
			item = content[start..].trim();
		}
		else {
			item = (usz)comma > start ? content[start..(usz)comma - 1].trim() : "";
		}
		if (!item.len) {
			return result::err(string::tformat("empty range at index %d", index));
		}
		Result{IPv6Range, String} range = parse_ipv6_range(item);
		if (!range.is_ok) {
			return result::err(string::tformat("invalid range at index %d: %s", index, range.error));
		}
		ranges.push(range.value);
		if (catch comma) break;
		start = (usz)comma + 1;
		index++;
	}
	return result::ok(ranges.to_tarray());
}
