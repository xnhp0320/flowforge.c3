module flowforge::constructor;
import flowforge::ast;
import flowforge::registry;
import flowforge::value;
import flowforge::cvalue;
import std::collections::list;
import std::collections::map;

faultdef BUILD_ERR;

struct FieldConstructor {
	String name;
	ConstructorValue value;
	bool explicitly_set;
}

struct OptionConstructor {
	String name;
	AttrValueKind value_kind;
	union {
		ConstructorValue scalar_value;
		PacketConstructor packet_value;
	}
	bool explicitly_set;
}

struct HeaderConstructor {
	String protocol;
	usz offset;
	FieldConstructor[] fields;
	OptionConstructor[] options;
}

typedef PacketConstructor = HeaderConstructor[];

struct BuildResult {
	bool ok;
	List{String} warnings;
	List{String} errors;
	PacketConstructor packet;
}

fn void BuildResult.tinit(&self) {
	self.warnings.tinit();
	self.errors.tinit();
}

fn ScalarValue? scalar_attribute_value(Attribute* attr, String* error) {
	ScalarValue? value = ast::attr_scalar(attr);
	if (catch value) {
		*error = "requires a value";
		return BUILD_ERR~;
	}
	if (value.kind == ScalarKind.PACKET) {
		*error = "requires a scalar value";
		return BUILD_ERR~;
	}
	return value;
}

fn Packet? packet_attribute_value(Attribute* attr, String* error) {
	ScalarValue? value = ast::attr_scalar(attr);
	if (catch value) {
		*error = "requires a value";
		return BUILD_ERR~;
	}
	if (value.kind != ScalarKind.PACKET) {
		*error = "requires a packet value";
		return BUILD_ERR~;
	}
	return value.packet_val;
}

fn ConstructorValue? construct_value(String type_name, usz bit_width, ScalarValue value, String* error) {
	usz? range_bit_width = cvalue::bit_range_width_for_type_name(type_name);
	if (try range_bit_width) {
		if (value.kind == ScalarKind.INTEGER) {
			if (!cvalue::validate_bit_value(value.int_val, range_bit_width, error)) return BUILD_ERR~;
			return value::cv_uint((ulong)value.int_val);
		}
		if (value.kind != ScalarKind.STRING) {
			*error = "expected integer or string value";
			return BUILD_ERR~;
		}
		String raw = value.string_val.trim();
		if ((raw.len && raw[0] == '[') || raw.ends_with("]") || raw.contains("-")) {
			UIntRange[]? ranges = cvalue::parse_uint_ranges(raw, range_bit_width, error);
			if (catch ranges) return BUILD_ERR~;
			return value::cv_uint_ranges(ranges);
		}
		ulong? scalar = cvalue::parse_uint_value(raw, range_bit_width, error);
		if (catch scalar) return BUILD_ERR~;
		return value::cv_uint(scalar);
	}

	if (type_name.len && type_name[0] == 'b') {
		if (value.kind != ScalarKind.INTEGER) {
			*error = "expected integer value";
			return BUILD_ERR~;
		}
		long integer = value.int_val;
		if (integer < 0) {
			*error = "negative integer value";
			return BUILD_ERR~;
		}
		if (!cvalue::validate_bit_value(integer, bit_width, error)) return BUILD_ERR~;
		return value::cv_uint((ulong)integer);
	}

	if (value.kind != ScalarKind.STRING) {
		*error = string::tformat("%s value must be a string", type_name);
		return BUILD_ERR~;
	}

	String s = value.string_val;
	if (type_name == "mac") {
		MacAddr? mac = value::mac_parse(s);
		if (catch mac) {
			*error = string::tformat("invalid mac address '%s'", s);
			return BUILD_ERR~;
		}
		return value::cv_mac(mac);
	}
	if (type_name == "ipv4") {
		IPv4? ip = value::ipv4_parse(s);
		if (catch ip) {
			*error = string::tformat("invalid ipv4 address '%s'", s);
			return BUILD_ERR~;
		}
		return value::cv_ipv4(ip);
	}
	if (type_name == "ipv6") {
		IPv6? ip = value::ipv6_parse(s);
		if (catch ip) {
			*error = string::tformat("invalid ipv6 address '%s'", s);
			return BUILD_ERR~;
		}
		return value::cv_ipv6(ip);
	}
	if (type_name == "ipv4_range") {
		IPv4Range? range = cvalue::parse_ipv4_range(s, error);
		if (catch range) return BUILD_ERR~;
		return value::cv_ipv4_range(range);
	}
	if (type_name == "ipv6_range") {
		IPv6Range? range = cvalue::parse_ipv6_range(s, error);
		if (catch range) return BUILD_ERR~;
		return value::cv_ipv6_range(range);
	}
	if (type_name == "ipv4_ranges") {
		IPv4Range[]? ranges = cvalue::parse_ipv4_ranges(s, error);
		if (catch ranges) return BUILD_ERR~;
		return value::cv_ipv4_ranges(ranges);
	}
	if (type_name == "ipv6_ranges") {
		IPv6Range[]? ranges = cvalue::parse_ipv6_ranges(s, error);
		if (catch ranges) return BUILD_ERR~;
		return value::cv_ipv6_ranges(ranges);
	}

	*error = string::tformat("unsupported constructor type '%s'", type_name);
	return BUILD_ERR~;
}

fn FieldConstructor* find_field(HeaderConstructor* header, String name) {
	foreach (&f : header.fields) {
		if (f.name == name) return f;
	}
	return null;
}

fn OptionConstructor* find_option(HeaderConstructor* header, String name) {
	foreach (&o : header.options) {
		if (o.name == name) return o;
	}
	return null;
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn usz packet_bit_width(PacketConstructor packet, Registry* registry) {
	usz bit_width = 0;
	foreach (header : packet) {
		HeaderSpec*? spec = registry.find_header(header.protocol);
		if (try spec) {
			usz w = header.offset * 8 + spec.bit_width;
			if (w > bit_width) bit_width = w;
		}
	}
	return bit_width;
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn usz packet_option_bit_width(OptionConstructor* option, Registry* registry) {
	if (option.value_kind != AttrValueKind.PACKET) return 0;
	usz bit_width = packet_bit_width(option.packet_value, registry);
	return ((bit_width + 31) / 32) * 32;
}

fn ulong? integer_option_value(HeaderConstructor* header, OptionConstructor* option, List{String}* errors) {
	if (option.value_kind == AttrValueKind.SCALAR) {
		ulong? v = value::cv_as_uint(option.scalar_value);
		if (try v) return v;
	}
	errors.push(string::tformat("option '%s.%s' is not an integer value", header.protocol, option.name));
	return BUILD_ERR~;
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn usz header_option_bit_width(HeaderConstructor* header, Registry* registry, List{String}* errors) {
	OptionConstructor* option = null;
	foreach (&o : header.options) {
		if (o.name == "options" && o.value_kind == AttrValueKind.PACKET) {
			option = o;
			break;
		}
	}
	if (!option) return 0;

	if (header.protocol != "IP" && header.protocol != "TCP") {
		errors.push(string::tformat("packet-valued option '%s.%s' is not serializable", header.protocol, option.name));
		return 0;
	}

	usz base_header_bytes = 20;
	usz option_bits = packet_option_bit_width(option, registry);
	usz header_bytes = base_header_bytes + option_bits / 8;
	if (header_bytes > 60) {
		errors.push(string::tformat("%s header with options is %d bytes but maximum is 60", header.protocol, header_bytes));
		return 0;
	}

	ulong words = (ulong)(header_bytes / 4);
	String field_name = header.protocol == "IP" ? "ihl" : "dataofs";
	FieldConstructor* length_field = find_field(header, field_name);
	if (!length_field) {
		errors.push(string::tformat("%s header is missing %s field", header.protocol, field_name));
		return 0;
	}

	if (length_field.explicitly_set) {
		ulong? current = value::cv_as_uint(length_field.value);
		bool mismatched = true;
		if (try current) mismatched = current != words;
		if (mismatched) {
			errors.push(string::tformat("explicit '%s.%s' does not match option header length %d words",
				header.protocol, field_name, words));
		}
	}
	else {
		length_field.value = value::cv_uint(words);
	}
	return option_bits;
}

fn usz payload_bit_width(HeaderConstructor* header, usz packet_bit_offset, List{String}* errors) {
	if (header.protocol != "Payload") return 0;

	OptionConstructor* length = find_option(header, "length");
	OptionConstructor* total_length = find_option(header, "total_length");
	if (!length) {
		errors.push("Payload header is missing length option");
		return 0;
	}

	if (total_length && total_length.explicitly_set) {
		if (length.explicitly_set) {
			errors.push("Payload length and total_length cannot both be explicitly set");
			return 0;
		}

		ulong? total_bytes = integer_option_value(header, total_length, errors);
		if (catch total_bytes) return 0;
		usz prefix_bytes = packet_bit_offset / 8;
		if (total_bytes < prefix_bytes) {
			errors.push(string::tformat("Payload total_length %d is smaller than preceding header length %d",
				total_bytes, prefix_bytes));
			return 0;
		}

		ulong payload_bytes = total_bytes - prefix_bytes;
		if (payload_bytes > 0xFFFFFFFFFFFFFFFF / 8) {
			errors.push(string::tformat("Payload length %d is too large", payload_bytes));
			return 0;
		}
		length.scalar_value = value::cv_uint(payload_bytes);
		return (usz)payload_bytes * 8;
	}

	ulong? length_bytes = integer_option_value(header, length, errors);
	if (catch length_bytes) return 0;
	if (length_bytes > 0xFFFFFFFFFFFFFFFF / 8) {
		errors.push(string::tformat("Payload length %d is too large", length_bytes));
		return 0;
	}
	return (usz)length_bytes * 8;
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn void apply_inference_rules(List{HeaderConstructor}* constructor, Registry* registry,
	List{String}* warnings, List{String}* errors) {
	usz n = (usz)constructor.len();
	if (n < 2) return;

	for (usz i = 0; i + 1 < n; i++) {
		HeaderConstructor* parent = constructor.get_ref((sz)i);
		HeaderConstructor* child = constructor.get_ref((sz)(i + 1));
		InferenceRule[] rules = registry.find_inference_rules(parent.protocol, child.protocol);

		foreach (rule : rules) {
			FieldConstructor* target = find_field(parent, rule.target_field);
			if (!target) {
				errors.push(string::tformat("inference rule '%s'/'%s' targets unknown field '%s.%s'",
					rule.parent_header, rule.child_header, parent.protocol, rule.target_field));
				continue;
			}

			if (target.explicitly_set) {
				if (!value::cv_equals(target.value, rule.value)) {
					warnings.push(string::tformat("explicit '%s.%s' overrides inference from next header '%s'",
						parent.protocol, rule.target_field, child.protocol));
				}
				continue;
			}

			target.value = rule.value;
		}
	}
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn BuildResult build(Registry* registry, Packet packet) {
	BuildResult result;
	result.tinit();
	List{HeaderConstructor} constructor;
	constructor.tinit();
	usz packet_bit_offset = 0;

	foreach (header : packet) {
		HeaderSpec*? header_spec = registry.find_header(header.protocol);
		if (catch header_spec) {
			result.errors.push(string::tformat("unknown header: '%s'", header.protocol));
			continue;
		}
		if (packet_bit_offset % 8 != 0) {
			result.errors.push(string::tformat("header '%s' starts at non-byte offset %d", header.protocol, packet_bit_offset));
			continue;
		}

		HashMap{String, Attribute} attrs;
		attrs.tinit();
		foreach (attr : header.attributes) {
			if (attrs.has_key(attr.name)) {
				result.errors.push(string::tformat("duplicate attribute '%s' in header '%s'", attr.name, header.protocol));
				continue;
			}
			attrs.set(attr.name, attr);
		}

		List{FieldConstructor} field_list;
		field_list.tinit();
		List{OptionConstructor} option_list;
		option_list.tinit();

		foreach (field : header_spec.fields) {
			Attribute? attr = attrs.get(field.name);
			if (catch attr) {
				field_list.push({ .name = field.name, .value = field.default_value, .explicitly_set = false });
				continue;
			}

			String err = "";
			ScalarValue? attr_value = scalar_attribute_value(&attr, &err);
			if (catch attr_value) {
				result.errors.push(string::tformat("attribute '%s' in header '%s' %s", attr.name, header.protocol, err));
				continue;
			}

			String verr = "";
			ConstructorValue? value = construct_value(field.type_name, field.bit_width, attr_value, &verr);
			if (catch value) {
				result.errors.push(string::tformat("invalid '%s' in header '%s': %s", attr.name, header.protocol, verr));
				continue;
			}
			field_list.push({ .name = field.name, .value = value, .explicitly_set = true });
		}

		foreach (option : header_spec.options) {
			Attribute? attr = attrs.get(option.name);
			if (catch attr) {
				ConstructorValue? def = option.default_value.get();
				if (try def) {
					option_list.push({
						.name = option.name,
						.value_kind = AttrValueKind.SCALAR,
						.scalar_value = def,
						.explicitly_set = false,
					});
				}
				continue;
			}

			if (option.value_kind == AttrValueKind.PACKET) {
				String err = "";
				Packet? packet_value = packet_attribute_value(&attr, &err);
				if (catch packet_value) {
					result.errors.push(string::tformat("attribute '%s' in header '%s' %s", attr.name, header.protocol, err));
					continue;
				}

				BuildResult nested = build(registry, packet_value);
				foreach (w : nested.warnings) result.warnings.push(w);
				if (!nested.ok) {
					foreach (nerr : nested.errors) {
						result.errors.push(string::tformat("invalid packet option '%s.%s': %s", header.protocol, attr.name, nerr));
					}
					continue;
				}

				option_list.push({
					.name = option.name,
					.value_kind = AttrValueKind.PACKET,
					.packet_value = nested.packet,
					.explicitly_set = true,
				});
			}
			else {
				String err = "";
				ScalarValue? attr_value = scalar_attribute_value(&attr, &err);
				if (catch attr_value) {
					result.errors.push(string::tformat("attribute '%s' in header '%s' %s", attr.name, header.protocol, err));
					continue;
				}

				String verr = "";
				usz opt_bit_width = cvalue::bit_width_for_type_name(option.type_name);
				ConstructorValue? value = construct_value(option.type_name, opt_bit_width, attr_value, &verr);
				if (catch value) {
					result.errors.push(string::tformat("invalid '%s' in header '%s': %s", attr.name, header.protocol, verr));
					continue;
				}
				option_list.push({
					.name = option.name,
					.value_kind = AttrValueKind.SCALAR,
					.scalar_value = value,
					.explicitly_set = true,
				});
			}
		}

		foreach (name : attrs.tkeys()) {
			bool known_field = false;
			foreach (f : header_spec.fields) {
				if (f.name == name) {
					known_field = true;
					break;
				}
			}
			bool known_option = false;
			foreach (o : header_spec.options) {
				if (o.name == name) {
					known_option = true;
					break;
				}
			}
			if (!known_field && !known_option) {
				result.errors.push(string::tformat("unknown attribute '%s' in header '%s'", name, header.protocol));
			}
		}

		HeaderConstructor header_constructor = {
			.protocol = header.protocol,
			.offset = packet_bit_offset / 8,
			.fields = field_list.to_tarray(),
			.options = option_list.to_tarray(),
		};

		usz option_bit_width = header_option_bit_width(&header_constructor, registry, &result.errors);

		constructor.push(header_constructor);
		packet_bit_offset += header_spec.bit_width + option_bit_width;
		if (packet_bit_offset % 8 == 0) {
			HeaderConstructor* last = constructor.get_ref((sz)constructor.len() - 1);
			packet_bit_offset += payload_bit_width(last, packet_bit_offset, &result.errors);
		}
	}

	if (result.errors.len() > 0) return result;

	apply_inference_rules(&constructor, registry, &result.warnings, &result.errors);

	if (result.errors.len() > 0) return result;

	result.ok = true;
	result.packet = (PacketConstructor)constructor.to_tarray();
	return result;
}
