module flowforge::registry;
import std::collections::map;
import std::collections::set;
import std::collections::list;
import flowforge::value;
import flowforge::cvalue;

alias StringSet = HashSet{String};
alias StringMap = HashMap{String, String};
alias HeaderAttrMap = HashMap{String, StringMap};

enum AttrValueKind {
	SCALAR,
	PACKET,
}

struct FieldSpec {
	String name;
	String type_name;
	usz bit_offset;
	usz bit_width;
	ConstructorValue default_value;
}

struct OptionSpec {
	String name;
	String type_name;
	AttrValueKind value_kind;
	bool has_default;
	ConstructorValue default_value;
}

struct HeaderSpec {
	String protocol;
	FieldSpec[] fields;
	OptionSpec[] options;
	usz bit_width;
}

struct InferenceRule {
	String parent_header;
	String child_header;
	String target_field;
	ConstructorValue value;
}

<* Input helper describing a field to register. *>
struct FieldInput {
	String name;
	String type_name;
	bool has_default;
	ConstructorValue default_value;
}

<* Input helper describing an option to register. *>
struct OptionInput {
	String name;
	String type_name;
	AttrValueKind value_kind;
	bool has_default;
	ConstructorValue default_value;
}

fn FieldInput fld(String name, String type_name) {
	return { .name = name, .type_name = type_name, .has_default = false };
}

fn FieldInput fldd(String name, String type_name, ConstructorValue default_value) {
	return { .name = name, .type_name = type_name, .has_default = true, .default_value = default_value };
}

fn OptionInput opt_scalar(String name, String type_name) {
	return { .name = name, .type_name = type_name, .value_kind = AttrValueKind.SCALAR, .has_default = false };
}

fn OptionInput opt_scalar_default(String name, String type_name, ConstructorValue default_value) {
	return { .name = name, .type_name = type_name, .value_kind = AttrValueKind.SCALAR, .has_default = true, .default_value = default_value };
}

fn OptionInput opt_packet(String name) {
	return { .name = name, .type_name = "", .value_kind = AttrValueKind.PACKET, .has_default = false };
}

struct Registry {
	HashMap{String, StringSet} attr_names;
	HeaderAttrMap attr_types;
	HashMap{String, String} failing_types;
	HashMap{String, HeaderSpec} header_specs;
	HashMap{String, List{InferenceRule}} inference_rules;
	Allocator allocator;
}

fn void Registry.init(&self, Allocator allocator) {
	self.allocator = allocator;
	self.attr_names.init(allocator);
	self.attr_types.init(allocator);
	self.failing_types.init(allocator);
	self.header_specs.init(allocator);
	self.inference_rules.init(allocator);
}

fn void Registry.tinit(&self) => self.init(tmem);

<* Legacy checker-oriented registration: populates attr names/types only. *>
fn void Registry.add_header(&self, String protocol, String[] field_names, String[] field_types, String[] packet_options) {
	StringMap types;
	types.init(self.allocator);
	StringSet names;
	names.init(self.allocator);

	for (usz i = 0; i < field_names.len; i++) {
		types.set(field_names[i], field_types[i]);
		names.add(field_names[i]);
	}
	foreach (name : packet_options) {
		names.add(name);
	}
	self.attr_types.set(protocol, types);
	self.attr_names.set(protocol, names);
}

<* Full registration: builds a HeaderSpec (with cumulative offsets) and keeps
   attr names/types in sync so the checker keeps working. *>
fn void Registry.register_header(&self, String protocol, FieldInput[] fields, OptionInput[] options = {}) {
	StringMap types;
	types.init(self.allocator);
	StringSet names;
	names.init(self.allocator);

	List{FieldSpec} field_list;
	field_list.init(self.allocator);
	List{OptionSpec} option_list;
	option_list.init(self.allocator);

	usz total_bits = 0;
	foreach (f : fields) {
		names.add(f.name);
		types.set(f.name, f.type_name);
		usz width = cvalue::bit_width_for_type_name(f.type_name);
		ConstructorValue def = f.has_default
			? f.default_value
			: cvalue::default_constructor_value_for_type(f.type_name);
		field_list.push({
			.name = f.name,
			.type_name = f.type_name,
			.bit_offset = total_bits,
			.bit_width = width,
			.default_value = def,
		});
		total_bits += width;
	}

	foreach (o : options) {
		names.add(o.name);
		if (o.value_kind == AttrValueKind.SCALAR) {
			types.set(o.name, o.type_name);
		}
		option_list.push({
			.name = o.name,
			.type_name = o.type_name,
			.value_kind = o.value_kind,
			.has_default = o.has_default,
			.default_value = o.default_value,
		});
	}

	HeaderSpec spec = {
		.protocol = protocol,
		.fields = field_list.to_array(self.allocator),
		.options = option_list.to_array(self.allocator),
		.bit_width = total_bits,
	};
	self.header_specs.set(protocol, spec);
	self.attr_names.set(protocol, names);
	self.attr_types.set(protocol, types);
}

<* Convenience alias used by tests to register a fields-only custom header. *>
fn void Registry.register_header_fields(&self, String protocol, FieldInput[] fields) {
	self.register_header(protocol, fields);
}

faultdef INFERENCE_ERR;

fn bool? Registry.register_inference_rule(&self, String parent_header, String child_header, String target_field, ConstructorValue value) {
	HeaderSpec*? parent_spec = self.header_specs.get_ref(parent_header);
	if (catch parent_spec) return INFERENCE_ERR~;
	if (!self.header_specs.has_key(child_header)) return INFERENCE_ERR~;

	FieldSpec* target = null;
	foreach (&f : parent_spec.fields) {
		if (f.name == target_field) {
			target = f;
			break;
		}
	}
	if (!target) return INFERENCE_ERR~;

	String err = "";
	if (!validate_constructor_value(target.type_name, value, &err)) return INFERENCE_ERR~;

	String key = inference_key(parent_header, child_header);
	if (!self.inference_rules.has_key(key)) {
		List{InferenceRule} rules;
		rules.init(self.allocator);
		self.inference_rules.set(key, rules);
	}
	List{InferenceRule}* rules = self.inference_rules.get_ref(key)!!;
	rules.push({
		.parent_header = parent_header,
		.child_header = child_header,
		.target_field = target_field,
		.value = value,
	});
	return true;
}

fn String inference_key(String parent, String child) {
	return string::tformat("%s\x1f%s", parent, child);
}

fn HeaderSpec*? Registry.find_header(&self, String protocol) {
	return self.header_specs.get_ref(protocol);
}

fn InferenceRule[] Registry.find_inference_rules(&self, String parent, String child) {
	String key = inference_key(parent, child);
	List{InferenceRule}*? rules = self.inference_rules.get_ref(key);
	if (catch rules) return {};
	return rules.array_view();
}

<* Validates a constructor value against a type. Returns true if valid,
   otherwise sets *error. Mirrors C++ validate_constructor_value. *>
fn bool validate_constructor_value(String type_name, ConstructorValue value, String* error) {
	usz bit_width = cvalue::bit_width_for_type_name(type_name);

	usz? range_bit_width = cvalue::bit_range_width_for_type_name(type_name);
	if (try range_bit_width) {
		if (value.kind != ConstructorValueKind.UINT) {
			if (value.kind != ConstructorValueKind.UINT_RANGES) {
				*error = "bit range constructor fields require integer or range list values";
				return false;
			}
			foreach (r : value.uint_ranges_val) {
				if (r.first > r.last) {
					*error = string::tformat("range %d-%d has first value greater than last value", r.first, r.last);
					return false;
				}
				if (!integer_fits(r.first, range_bit_width, error)) return false;
				if (!integer_fits(r.last, range_bit_width, error)) return false;
			}
			return true;
		}
		return integer_fits(value.uint_val, range_bit_width, error);
	}

	if (type_name.len && type_name[0] == 'b') {
		if (value.kind != ConstructorValueKind.UINT) {
			*error = "bit constructor fields require integer values";
			return false;
		}
		return integer_fits(value.uint_val, bit_width, error);
	}
	if (type_name == "mac") {
		if (value.kind == ConstructorValueKind.MAC) return true;
		*error = "mac constructor fields require mac address values";
		return false;
	}
	if (type_name == "ipv4") {
		if (value.kind == ConstructorValueKind.IPV4) return true;
		*error = "ipv4 constructor fields require ipv4 address values";
		return false;
	}
	if (type_name == "ipv6") {
		if (value.kind == ConstructorValueKind.IPV6) return true;
		*error = "ipv6 constructor fields require ipv6 address values";
		return false;
	}
	if (type_name == "ipv4_range") {
		if (value.kind == ConstructorValueKind.IPV4_RANGE) return true;
		*error = "ipv4 range constructor fields require ipv4 range values";
		return false;
	}
	if (type_name == "ipv6_range") {
		if (value.kind == ConstructorValueKind.IPV6_RANGE) return true;
		*error = "ipv6 range constructor fields require ipv6 range values";
		return false;
	}
	if (type_name == "ipv4_ranges") {
		if (value.kind == ConstructorValueKind.IPV4_RANGES) return true;
		*error = "ipv4 ranges constructor fields require ipv4 range list values";
		return false;
	}
	if (type_name == "ipv6_ranges") {
		if (value.kind == ConstructorValueKind.IPV6_RANGES) return true;
		*error = "ipv6 ranges constructor fields require ipv6 range list values";
		return false;
	}

	*error = string::tformat("unsupported constructor type '%s'", type_name);
	return false;
}

fn bool integer_fits(ulong integer, usz bit_width, String* error) {
	if (bit_width < 64 && integer > ((1UL << bit_width) - 1)) {
		*error = string::tformat("value %d does not fit in %d bits", integer, bit_width);
		return false;
	}
	return true;
}

fn void Registry.register_defaults(&self) {
	self.register_header("Ether", {
		fld("dst", "mac"),
		fld("src", "mac"),
		fld("type", "b16"),
	});

	self.register_header("IP", {
		fldd("version", "b4", value::cv_uint(4)),
		fldd("ihl", "b4", value::cv_uint(5)),
		fld("tos", "b8"),
		fld("len", "b16"),
		fld("id", "b16"),
		fld("flags", "b3"),
		fld("frag", "b13"),
		fldd("ttl", "b8", value::cv_uint(64)),
		fld("proto", "b8"),
		fld("chksum", "b16"),
		fld("src", "ipv4_ranges"),
		fld("dst", "ipv4_ranges"),
	}, {
		opt_packet("options"),
	});

	self.register_header("IPv6", {
		fldd("version", "b4", value::cv_uint(6)),
		fld("tc", "b8"),
		fld("fl", "b20"),
		fld("len", "b16"),
		fld("nh", "b8"),
		fldd("hlim", "b8", value::cv_uint(64)),
		fld("src", "ipv6_ranges"),
		fld("dst", "ipv6_ranges"),
	});

	self.register_header("TCP", {
		fld("sport", "b16_ranges"),
		fld("dport", "b16_ranges"),
		fld("seq", "b32"),
		fld("ack", "b32"),
		fldd("dataofs", "b4", value::cv_uint(5)),
		fld("reserved", "b3"),
		fld("flags", "b9"),
		fld("window", "b16"),
		fld("chksum", "b16"),
		fld("urgptr", "b16"),
	}, {
		opt_packet("options"),
	});

	self.register_header("UDP", {
		fld("sport", "b16_ranges"),
		fld("dport", "b16_ranges"),
		fld("len", "b16"),
		fld("chksum", "b16"),
	});

	self.register_header("ICMP", {
		fld("type", "b8"),
		fld("code", "b8"),
		fld("chksum", "b16"),
		fld("id", "b16"),
		fld("seq", "b16"),
	});

	self.register_header("VLAN", {
		fld("prio", "b3"),
		fld("dei", "b1"),
		fld("vlan", "b12"),
		fld("type", "b16"),
	});

	self.register_header("VXLAN", {
		fldd("flags", "b8", value::cv_uint(0x08)),
		fld("reserved", "b24"),
		fld("vni", "b24"),
		fld("reserved2", "b8"),
	});

	self.register_header("Payload", {}, {
		opt_scalar_default("length", "b64", value::cv_uint(0)),
		opt_scalar("total_length", "b64"),
	});

	self.register_header("IPOption_EOL", { fldd("type", "b8", value::cv_uint(0)) });
	self.register_header("IPOption_NOP", { fldd("type", "b8", value::cv_uint(1)) });
	self.register_header("TCPOption_EOL", { fldd("kind", "b8", value::cv_uint(0)) });
	self.register_header("TCPOption_NOP", { fldd("kind", "b8", value::cv_uint(1)) });
	self.register_header("TCPOption_MSS", {
		fldd("kind", "b8", value::cv_uint(2)),
		fldd("length", "b8", value::cv_uint(4)),
		fld("value", "b16"),
	});
	self.register_header("TCPOption_WS", {
		fldd("kind", "b8", value::cv_uint(3)),
		fldd("length", "b8", value::cv_uint(3)),
		fld("shift", "b8"),
	});
	self.register_header("TCPOption_SACKPermitted", {
		fldd("kind", "b8", value::cv_uint(4)),
		fldd("length", "b8", value::cv_uint(2)),
	});
	self.register_header("TCPOption_Timestamp", {
		fldd("kind", "b8", value::cv_uint(8)),
		fldd("length", "b8", value::cv_uint(10)),
		fld("tsval", "b32"),
		fld("tsecr", "b32"),
	});

	self.register_inference_rule("Ether", "IP", "type", value::cv_uint(0x0800))!!;
	self.register_inference_rule("Ether", "IPv6", "type", value::cv_uint(0x86dd))!!;
	self.register_inference_rule("Ether", "VLAN", "type", value::cv_uint(0x8100))!!;
	self.register_inference_rule("VLAN", "IP", "type", value::cv_uint(0x0800))!!;
	self.register_inference_rule("VLAN", "IPv6", "type", value::cv_uint(0x86dd))!!;
	self.register_inference_rule("IP", "TCP", "proto", value::cv_uint(6))!!;
	self.register_inference_rule("IP", "UDP", "proto", value::cv_uint(17))!!;
	self.register_inference_rule("IP", "ICMP", "proto", value::cv_uint(1))!!;
	self.register_inference_rule("IPv6", "TCP", "nh", value::cv_uint(6))!!;
	self.register_inference_rule("IPv6", "UDP", "nh", value::cv_uint(17))!!;
	self.register_inference_rule("IPv6", "ICMP", "nh", value::cv_uint(58))!!;
	self.register_inference_rule("UDP", "VXLAN", "dport", value::cv_uint(4789))!!;
}

fn Registry create_default_registry() {
	Registry reg;
	reg.tinit();
	reg.register_defaults();
	return reg;
}

fn Registry create_empty_registry() {
	Registry reg;
	reg.tinit();
	return reg;
}

fn bool Registry.has_header(&self, String protocol) => self.attr_names.has_key(protocol);

fn bool Registry.has_attr(&self, String protocol, String attr) {
	if (!self.attr_names.has_key(protocol)) return false;
	StringSet names = self.attr_names.get(protocol)!!;
	return names.contains(attr);
}

faultdef NO_ATTR;

fn String? Registry.attr_type(&self, String protocol, String attr) {
	if (!self.attr_types.has_key(protocol)) return NO_ATTR~;
	StringMap types = self.attr_types.get(protocol)!!;
	if (!types.has_key(attr)) return NO_ATTR~;
	return types.get(attr);
}

fn void Registry.add_failing_type(&self, String type_name, String message) {
	self.failing_types.set(type_name, message);
}

fn String? Registry.failing_type_message(&self, String type_name) {
	if (!self.failing_types.has_key(type_name)) return NO_ATTR~;
	return self.failing_types.get(type_name);
}

fn void Registry.free(&self) {
	self.attr_names.free();
	self.attr_types.free();
	self.failing_types.free();
	self.header_specs.free();
	self.inference_rules.free();
}
