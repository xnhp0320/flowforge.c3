module flowforge::registry;
import std::collections::map;
import std::collections::set;

alias StringSet = HashSet{String};
alias StringMap = HashMap{String, String};
alias HeaderAttrMap = HashMap{String, StringMap};

struct Registry {
	HashMap{String, StringSet} attr_names;
	HeaderAttrMap attr_types;
	HashMap{String, String} failing_types;
	Allocator allocator;
}

fn void Registry.init(&self, Allocator allocator) {
	self.allocator = allocator;
	self.attr_names.init(allocator);
	self.attr_types.init(allocator);
	self.failing_types.init(allocator);
}

fn void Registry.tinit(&self) => self.init(tmem);

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

fn void Registry.register_defaults(&self) {
	self.add_header("Ether",
		{ "dst", "src", "type" },
		{ "mac", "mac", "b16" },
		{});

	self.add_header("IP",
		{ "version", "ihl", "tos", "len", "id", "flags", "frag", "ttl", "proto", "chksum", "src", "dst" },
		{ "b4", "b4", "b8", "b16", "b16", "b3", "b13", "b8", "b8", "b16", "ipv4_ranges", "ipv4_ranges" },
		{ "options" });

	self.add_header("IPv6",
		{ "version", "tc", "fl", "len", "nh", "hlim", "src", "dst" },
		{ "b4", "b8", "b20", "b16", "b8", "b8", "ipv6_ranges", "ipv6_ranges" },
		{ "options" });

	self.add_header("TCP",
		{ "sport", "dport", "seq", "ack", "dataofs", "reserved", "flags", "window", "chksum", "urgptr" },
		{ "b16_ranges", "b16_ranges", "b32", "b32", "b4", "b3", "b9", "b16", "b16", "b16" },
		{ "options" });

	self.add_header("UDP",
		{ "sport", "dport", "len", "chksum" },
		{ "b16_ranges", "b16_ranges", "b16", "b16" },
		{});

	self.add_header("ICMP",
		{ "type", "code", "chksum", "id", "seq" },
		{ "b8", "b8", "b16", "b16", "b16" },
		{});

	self.add_header("VLAN",
		{ "prio", "dei", "vlan", "type" },
		{ "b3", "b1", "b12", "b16" },
		{});

	self.add_header("VXLAN",
		{ "flags", "reserved", "vni", "reserved2" },
		{ "b8", "b24", "b24", "b8" },
		{});

	self.add_header("Payload",
		{ "length", "total_length" },
		{ "b64", "b64" },
		{});

	self.add_header("IPOption_EOL", { "type" }, { "b8" }, {});
	self.add_header("IPOption_NOP", { "type" }, { "b8" }, {});
	self.add_header("TCPOption_EOL", { "kind" }, { "b8" }, {});
	self.add_header("TCPOption_NOP", { "kind" }, { "b8" }, {});
	self.add_header("TCPOption_MSS", { "kind", "length", "value" }, { "b8", "b8", "b16" }, {});
	self.add_header("TCPOption_WS", { "kind", "length", "shift" }, { "b8", "b8", "b8" }, {});
	self.add_header("TCPOption_SACKPermitted", { "kind", "length" }, { "b8", "b8" }, {});
	self.add_header("TCPOption_Timestamp", { "kind", "length", "tsval", "tsecr" }, { "b8", "b8", "b32", "b32" }, {});
}

fn Registry create_default_registry() {
	Registry reg;
	reg.tinit();
	reg.register_defaults();
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
}
