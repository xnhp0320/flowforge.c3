module flowforge::serializer;
import flowforge::constructor;
import flowforge::cvalue;
import flowforge::registry;
import flowforge::value;
import std::collections::list;

faultdef SERIALIZE_ERR, NO_MODIFIER, OUT_OF_RANGE, HEADER_NOT_FOUND;

const char TCP_PROTOCOL = 6;
const char UDP_PROTOCOL = 17;

enum ModifierValueKind {
	UINT_RANGES,
	IPV4_RANGES,
	IPV6_RANGES,
}

struct PayloadFieldModifier {
	String protocol;
	String field;
	usz bit_offset;
	usz bit_width;
	ulong value_count;
	ModifierValueKind values_kind;
	union {
		UIntRange[] uint_ranges;
		IPv4Range[] ipv4_ranges;
		IPv6Range[] ipv6_ranges;
	}
}

struct SerializeResult {
	bool ok;
	String[] errors;
	usz packet_len;
	PayloadFieldModifier[] modifiers;
}

enum FixupMode {
	SOFTWARE,
	HARDWARE_OFFLOAD,
	DISABLED,
}

struct FixupOptions {
	FixupMode ipv4_checksum;
	FixupMode tcp_checksum;
	FixupMode udp_checksum;
	FixupMode icmp_checksum;
}

enum OffloadLayer3 {
	NONE,
	IPV4,
	IPV6,
}

struct PacketOffloadRequest {
	OffloadLayer3 layer3;
	bool ipv4_checksum;
	bool tcp_checksum;
	bool udp_checksum;
	usz l2_len;
	usz l3_len;
	usz l4_len;
}

struct Ipv4Fixup {
	usz offset;
	usz header_len;
	FixupMode checksum;
}

struct Ipv6Fixup {
	usz offset;
	usz header_len;
}

struct UdpFixup {
	usz offset;
	FixupMode checksum;
}

struct TcpFixup {
	usz offset;
	usz header_len;
	FixupMode checksum;
}

struct IcmpFixup {
	usz offset;
	FixupMode checksum;
}

struct PacketFixupPlan {
	usz packet_len;
	bool has_ipv4;
	Ipv4Fixup ipv4;
	bool has_ipv6;
	Ipv6Fixup ipv6;
	bool has_udp;
	UdpFixup udp;
	bool has_tcp;
	TcpFixup tcp;
	bool has_icmp;
	IcmpFixup icmp;
	PacketOffloadRequest offload;
}

struct FixupPlanResult {
	bool ok;
	String[] errors;
	PacketFixupPlan plan;
}

struct FixupResult {
	bool ok;
	String[] errors;
	PacketOffloadRequest offload;
}

// --- bit/byte writers -------------------------------------------------

fn void write_bit(char[] payload, usz bit_offset, bool bit) {
	usz byte_idx = bit_offset / 8;
	char mask = (char)(1u << (7 - bit_offset % 8));
	if (bit) {
		payload[byte_idx] = (char)(payload[byte_idx] | mask);
	}
	else {
		payload[byte_idx] = (char)(payload[byte_idx] & ~mask);
	}
}

fn void write_bits(char[] payload, usz bit_offset, usz bit_width, ulong value) {
	for (usz bit = 0; bit < bit_width; bit++) {
		usz shift = bit_width - bit - 1;
		write_bit(payload, bit_offset + bit, ((value >> shift) & 1) != 0);
	}
}

fn void write_bytes(char[] payload, usz bit_offset, char[] bytes) {
	if (bit_offset % 8 == 0) {
		usz byte_offset = bit_offset / 8;
		for (usz i = 0; i < bytes.len; i++) payload[byte_offset + i] = bytes[i];
	}
	else {
		for (usz i = 0; i < bytes.len; i++) {
			write_bits(payload, bit_offset + i * 8, 8, bytes[i]);
		}
	}
}

fn char read_u8(char[] payload, usz offset) => payload[offset];

fn ushort read_u16(char[] payload, usz offset) {
	return (ushort)(((ushort)read_u8(payload, offset) << 8) | (ushort)read_u8(payload, offset + 1));
}

fn void write_u16(char[] payload, usz offset, ushort value) {
	payload[offset] = (char)(value >> 8);
	payload[offset + 1] = (char)(value & 0xff);
}

// --- range counting / addressing --------------------------------------

fn ulong saturated_add_count(ulong left, ulong right) {
	if (ulong::max - left < right) return ulong::max;
	return left + right;
}

fn ulong uint_range_count(UIntRange r) {
	if (r.last - r.first == ulong::max) return ulong::max;
	return r.last - r.first + 1;
}

fn ulong ipv4_range_count(IPv4Range r) {
	return (ulong)(cvalue::ipv4_to_u32(r.last) - cvalue::ipv4_to_u32(r.first)) + 1;
}

fn ulong ipv6_range_count(IPv6Range r) {
	char[16] first = r.first.bytes;
	char[16] last = r.last.bytes;
	char[16] diff;
	int borrow = 0;
	for (usz idx = 16; idx > 0; idx--) {
		int minuend = (int)last[idx - 1];
		int subtrahend = (int)first[idx - 1] + borrow;
		if (minuend < subtrahend) {
			diff[idx - 1] = (char)(minuend + 256 - subtrahend);
			borrow = 1;
		}
		else {
			diff[idx - 1] = (char)(minuend - subtrahend);
			borrow = 0;
		}
	}

	for (usz i = 0; i < 8; i++) {
		if (diff[i] != 0) return ulong::max;
	}

	ulong value = 0;
	for (usz i = 8; i < 16; i++) {
		value = (value << 8) | diff[i];
	}
	return value == ulong::max ? ulong::max : value + 1;
}

fn ulong total_uint_value_count(UIntRange[] ranges) {
	ulong total = 0;
	foreach (r : ranges) total = saturated_add_count(total, uint_range_count(r));
	return total;
}

fn ulong total_ipv4_value_count(IPv4Range[] ranges) {
	ulong total = 0;
	foreach (r : ranges) total = saturated_add_count(total, ipv4_range_count(r));
	return total;
}

fn ulong total_ipv6_value_count(IPv6Range[] ranges) {
	ulong total = 0;
	foreach (r : ranges) total = saturated_add_count(total, ipv6_range_count(r));
	return total;
}

struct UIntRangeAt {
	UIntRange range;
	ulong offset;
}

struct Ipv4RangeAt {
	IPv4Range range;
	ulong offset;
}

struct Ipv6RangeAt {
	IPv6Range range;
	ulong offset;
}

fn UIntRangeAt? uint_range_at_index(UIntRange[] ranges, ulong value_index) {
	foreach (r : ranges) {
		ulong count = uint_range_count(r);
		if (value_index < count) return { .range = r, .offset = value_index };
		value_index -= count;
	}
	return OUT_OF_RANGE~;
}

fn Ipv4RangeAt? ipv4_range_at_index(IPv4Range[] ranges, ulong value_index) {
	foreach (r : ranges) {
		ulong count = ipv4_range_count(r);
		if (value_index < count) return { .range = r, .offset = value_index };
		value_index -= count;
	}
	return OUT_OF_RANGE~;
}

fn Ipv6RangeAt? ipv6_range_at_index(IPv6Range[] ranges, ulong value_index) {
	foreach (r : ranges) {
		ulong count = ipv6_range_count(r);
		if (value_index < count) return { .range = r, .offset = value_index };
		value_index -= count;
	}
	return OUT_OF_RANGE~;
}

fn IPv6 add_ipv6_offset(IPv6 ip, ulong offset) {
	char[16] bytes = ip.bytes;
	ushort carry = 0;
	for (usz index = 16; index > 0; index--) {
		usz shift = (16 - index) * 8;
		ushort addend = shift < 64 ? (ushort)((offset >> shift) & 0xff) : 0;
		ushort sum = (ushort)((ushort)bytes[index - 1] + addend + carry);
		bytes[index - 1] = (char)(sum & 0xff);
		carry = (ushort)(sum >> 8);
	}
	return value::ipv6_from_bytes(bytes);
}

// --- PayloadFieldModifier ----------------------------------------------

fn bool PayloadFieldModifier.apply(&self, char[] payload, ulong value_index, String* error) {
	if (self.bit_width > usz::max - self.bit_offset || (self.bit_offset + self.bit_width + 7) / 8 > payload.len) {
		*error = string::tformat("payload is too small for modifier '%s.%s'", self.protocol, self.field);
		return false;
	}

	switch (self.values_kind) {
		case UINT_RANGES:
			UIntRangeAt? found = uint_range_at_index(self.uint_ranges, value_index);
			if (catch found) {
				*error = string::tformat("value index %d is out of range for modifier '%s.%s'", value_index, self.protocol, self.field);
				return false;
			}
			write_bits(payload, self.bit_offset, self.bit_width, found.range.first + found.offset);
			return true;
		case IPV4_RANGES:
			Ipv4RangeAt? found = ipv4_range_at_index(self.ipv4_ranges, value_index);
			if (catch found) {
				*error = string::tformat("value index %d is out of range for modifier '%s.%s'", value_index, self.protocol, self.field);
				return false;
			}
			IPv4 ip = cvalue::ipv4_from_u32(cvalue::ipv4_to_u32(found.range.first) + (uint)found.offset);
			write_bytes(payload, self.bit_offset, ip.bytes[..]);
			return true;
		case IPV6_RANGES:
			Ipv6RangeAt? found = ipv6_range_at_index(self.ipv6_ranges, value_index);
			if (catch found) {
				*error = string::tformat("value index %d is out of range for modifier '%s.%s'", value_index, self.protocol, self.field);
				return false;
			}
			IPv6 ip = add_ipv6_offset(found.range.first, found.offset);
			write_bytes(payload, self.bit_offset, ip.bytes[..]);
			return true;
	}
}

// --- packet layout helpers (mirrors constructor.c3's own local layout
// math, but also accounts for header options and Payload length so that
// the full serialized buffer size can be computed) --------------------

fn usz payload_bit_width(HeaderConstructor header) {
	if (header.protocol != "Payload") return 0;
	OptionConstructor* length = constructor::find_option(&header, "length");
	if (!length) return 0;
	if (length.value_kind != AttrValueKind.SCALAR) return 0;
	if (length.scalar_value.kind != ConstructorValueKind.UINT) return 0;
	ulong length_bytes = length.scalar_value.uint_val;
	if (length_bytes > ulong::max / 8) return usz::max;
	return (usz)(length_bytes * 8);
}

fn usz packet_bit_width(PacketConstructor packet, Registry* registry) {
	usz bit_width = 0;
	foreach (header : packet) {
		HeaderSpec*? spec = registry.find_header(header.protocol);
		if (try spec) {
			usz w = header.offset * 8 + spec.bit_width + header_option_bit_width(header, registry) + payload_bit_width(header);
			if (w > bit_width) bit_width = w;
		}
	}
	return bit_width;
}

fn usz packet_option_bit_width(OptionConstructor option, Registry* registry) {
	if (option.value_kind != AttrValueKind.PACKET) return 0;
	usz bit_width = packet_bit_width(option.packet_value, registry);
	return ((bit_width + 31) / 32) * 32;
}

fn usz header_option_bit_width(HeaderConstructor header, Registry* registry) {
	if (header.protocol != "IP" && header.protocol != "TCP") return 0;
	OptionConstructor* options = constructor::find_option(&header, "options");
	if (!options) return 0;
	return packet_option_bit_width(*options, registry);
}

fn FieldSpec* find_field_spec(HeaderSpec* header, String name) {
	foreach (&f : header.fields) {
		if (f.name == name) return f;
	}
	return null;
}

// --- field/value serialization -----------------------------------------

fn ulong? first_integer_value(ConstructorValue value, String field_name, String* error) {
	if (value.kind == ConstructorValueKind.UINT) return value.uint_val;
	if (value.kind == ConstructorValueKind.UINT_RANGES) {
		if (value.uint_ranges_val.len == 0) {
			*error = string::tformat("field '%s' has an empty integer range list", field_name);
			return SERIALIZE_ERR~;
		}
		return value.uint_ranges_val[0].first;
	}
	*error = string::tformat("field '%s' is not an integer value", field_name);
	return SERIALIZE_ERR~;
}

fn IPv4? first_ipv4_value(ConstructorValue value, String field_name, String* error) {
	if (value.kind == ConstructorValueKind.IPV4) return value.ipv4_val;
	if (value.kind == ConstructorValueKind.IPV4_RANGE) return value.ipv4_range_val.first;
	if (value.kind == ConstructorValueKind.IPV4_RANGES) {
		if (value.ipv4_ranges_val.len == 0) {
			*error = string::tformat("field '%s' has an empty ipv4 range list", field_name);
			return SERIALIZE_ERR~;
		}
		return value.ipv4_ranges_val[0].first;
	}
	*error = string::tformat("field '%s' is not an ipv4 value", field_name);
	return SERIALIZE_ERR~;
}

fn IPv6? first_ipv6_value(ConstructorValue value, String field_name, String* error) {
	if (value.kind == ConstructorValueKind.IPV6) return value.ipv6_val;
	if (value.kind == ConstructorValueKind.IPV6_RANGE) return value.ipv6_range_val.first;
	if (value.kind == ConstructorValueKind.IPV6_RANGES) {
		if (value.ipv6_ranges_val.len == 0) {
			*error = string::tformat("field '%s' has an empty ipv6 range list", field_name);
			return SERIALIZE_ERR~;
		}
		return value.ipv6_ranges_val[0].first;
	}
	*error = string::tformat("field '%s' is not an ipv6 value", field_name);
	return SERIALIZE_ERR~;
}

fn bool serialize_field(FieldSpec* spec, FieldConstructor field, usz bit_offset, char[] payload, List{String}* errors) {
	String type = spec.type_name;
	if (type == "mac") {
		if (field.value.kind != ConstructorValueKind.MAC) {
			errors.push(string::tformat("field '%s' is not a mac value", field.name));
			return false;
		}
		write_bytes(payload, bit_offset, field.value.mac_val.bytes[..]);
		return true;
	}
	if (type == "ipv4" || type == "ipv4_range" || type == "ipv4_ranges") {
		String err = "";
		IPv4? ip = first_ipv4_value(field.value, field.name, &err);
		if (catch ip) {
			errors.push(err);
			return false;
		}
		write_bytes(payload, bit_offset, ip.bytes[..]);
		return true;
	}
	if (type == "ipv6" || type == "ipv6_range" || type == "ipv6_ranges") {
		String err = "";
		IPv6? ip = first_ipv6_value(field.value, field.name, &err);
		if (catch ip) {
			errors.push(err);
			return false;
		}
		write_bytes(payload, bit_offset, ip.bytes[..]);
		return true;
	}

	String err = "";
	ulong? integer = first_integer_value(field.value, field.name, &err);
	if (catch integer) {
		errors.push(err);
		return false;
	}
	write_bits(payload, bit_offset, spec.bit_width, integer);
	return true;
}

fn PayloadFieldModifier? make_modifier(HeaderConstructor header, FieldSpec* spec, FieldConstructor field, usz bit_offset, List{String}* errors) {
	PayloadFieldModifier modifier;
	modifier.protocol = header.protocol;
	modifier.field = field.name;
	modifier.bit_offset = bit_offset;
	modifier.bit_width = spec.bit_width;

	switch (field.value.kind) {
		case IPV4_RANGE:
			IPv4Range[] one = mem::temp_array(IPv4Range, 1);
			one[0] = field.value.ipv4_range_val;
			modifier.values_kind = ModifierValueKind.IPV4_RANGES;
			modifier.ipv4_ranges = one;
			modifier.value_count = ipv4_range_count(field.value.ipv4_range_val);
			return modifier;
		case IPV6_RANGE:
			IPv6Range[] one = mem::temp_array(IPv6Range, 1);
			one[0] = field.value.ipv6_range_val;
			modifier.values_kind = ModifierValueKind.IPV6_RANGES;
			modifier.ipv6_ranges = one;
			modifier.value_count = ipv6_range_count(field.value.ipv6_range_val);
			return modifier;
		case UINT_RANGES:
			UIntRange[] ranges = field.value.uint_ranges_val;
			if (ranges.len == 0) {
				errors.push(string::tformat("field '%s' has an empty integer range list", field.name));
				return NO_MODIFIER~;
			}
			modifier.values_kind = ModifierValueKind.UINT_RANGES;
			modifier.uint_ranges = ranges;
			modifier.value_count = total_uint_value_count(ranges);
			return modifier;
		case IPV4_RANGES:
			IPv4Range[] ranges4 = field.value.ipv4_ranges_val;
			if (ranges4.len == 0) {
				errors.push(string::tformat("field '%s' has an empty ipv4 range list", field.name));
				return NO_MODIFIER~;
			}
			modifier.values_kind = ModifierValueKind.IPV4_RANGES;
			modifier.ipv4_ranges = ranges4;
			modifier.value_count = total_ipv4_value_count(ranges4);
			return modifier;
		case IPV6_RANGES:
			IPv6Range[] ranges6 = field.value.ipv6_ranges_val;
			if (ranges6.len == 0) {
				errors.push(string::tformat("field '%s' has an empty ipv6 range list", field.name));
				return NO_MODIFIER~;
			}
			modifier.values_kind = ModifierValueKind.IPV6_RANGES;
			modifier.ipv6_ranges = ranges6;
			modifier.value_count = total_ipv6_value_count(ranges6);
			return modifier;
		default:
			return NO_MODIFIER~;
	}
}

fn void serialize_option_packet(HeaderConstructor parent, OptionConstructor option, Registry* registry, usz start_bit_offset, char[] payload, List{String}* errors) {
	if (parent.protocol != "IP" && parent.protocol != "TCP") {
		errors.push(string::tformat("packet-valued option '%s.%s' is not serializable", parent.protocol, option.name));
		return;
	}
	if (option.value_kind != AttrValueKind.PACKET) return;

	foreach (header : option.packet_value) {
		HeaderSpec*? header_spec = registry.find_header(header.protocol);
		if (catch header_spec) {
			errors.push(string::tformat("unknown option header: '%s'", header.protocol));
			continue;
		}

		foreach (field : header.fields) {
			FieldSpec* spec = find_field_spec(header_spec, field.name);
			if (!spec) {
				errors.push(string::tformat("unknown field '%s' in option header '%s'", field.name, header.protocol));
				continue;
			}
			serialize_field(spec, field, start_bit_offset + header.offset * 8 + spec.bit_offset, payload, errors);
		}
	}
}

fn SerializeResult serialize_packet(PacketConstructor packet, Registry* registry, char[] output) {
	SerializeResult result;
	List{String} errors;
	errors.tinit();
	List{PayloadFieldModifier} modifiers;
	modifiers.tinit();

	usz bit_width = packet_bit_width(packet, registry);
	if (bit_width % 8 != 0) {
		errors.push(string::tformat("packet bit width %d is not byte-aligned", bit_width));
		result.errors = errors.to_tarray();
		return result;
	}

	result.packet_len = bit_width / 8;
	if (output.len < result.packet_len) {
		errors.push(string::tformat("output buffer has %d bytes but packet requires %d bytes", output.len, result.packet_len));
		result.errors = errors.to_tarray();
		return result;
	}

	for (usz i = 0; i < result.packet_len; i++) output[i] = 0;

	foreach (header : packet) {
		HeaderSpec*? header_spec = registry.find_header(header.protocol);
		if (catch header_spec) {
			errors.push(string::tformat("unknown header: '%s'", header.protocol));
			continue;
		}

		foreach (field : header.fields) {
			FieldSpec* spec = find_field_spec(header_spec, field.name);
			if (!spec) {
				errors.push(string::tformat("unknown field '%s' in header '%s'", field.name, header.protocol));
				continue;
			}

			usz bit_offset = header.offset * 8 + spec.bit_offset;
			if (serialize_field(spec, field, bit_offset, output, &errors)) {
				PayloadFieldModifier? modifier = make_modifier(header, spec, field, bit_offset, &errors);
				if (try modifier) modifiers.push(modifier);
			}
		}

		foreach (option : header.options) {
			if (option.value_kind == AttrValueKind.PACKET) {
				serialize_option_packet(header, option, registry, header.offset * 8 + header_spec.bit_width, output, &errors);
			}
		}
	}

	result.modifiers = modifiers.to_tarray();
	result.errors = errors.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

// --- checksum helpers ----------------------------------------------------

fn uint checksum_sum(char[] bytes) {
	uint sum = 0;
	usz offset = 0;
	while (offset + 1 < bytes.len) {
		sum += read_u16(bytes, offset);
		offset += 2;
	}
	if (offset < bytes.len) {
		sum += (uint)((uint)read_u8(bytes, offset) << 8);
	}
	return sum;
}

fn uint add_u16(uint sum, ushort value) => sum + value;

fn ushort fold_checksum(uint sum) {
	while ((sum >> 16) != 0) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	return (ushort)sum;
}

fn ushort internet_checksum(uint sum) {
	ushort folded = fold_checksum(sum);
	return (ushort)(~(uint)folded & 0xffff);
}

fn uint ipv4_pseudo_sum(char[] payload, usz ip_offset, char protocol, ushort l4_len) {
	uint sum = 0;
	sum += read_u16(payload, ip_offset + 12);
	sum += read_u16(payload, ip_offset + 14);
	sum += read_u16(payload, ip_offset + 16);
	sum += read_u16(payload, ip_offset + 18);
	sum = add_u16(sum, (ushort)protocol);
	sum = add_u16(sum, l4_len);
	return sum;
}

fn uint ipv6_pseudo_sum(char[] payload, usz ip_offset, char protocol, uint l4_len) {
	uint sum = checksum_sum(payload[ip_offset + 8 : 32]);
	sum = add_u16(sum, (ushort)(l4_len >> 16));
	sum = add_u16(sum, (ushort)(l4_len & 0xffff));
	sum = add_u16(sum, (ushort)protocol);
	return sum;
}

// --- fixup planning / application ----------------------------------------

struct HeaderRef {
	HeaderConstructor* header;
	HeaderSpec* spec;
}

fn HeaderRef? find_header_ref(PacketConstructor packet, Registry* registry, String protocol) {
	foreach (&h : packet) {
		if (h.protocol == protocol) {
			HeaderSpec*? spec = registry.find_header(h.protocol);
			if (catch spec) return HEADER_NOT_FOUND~;
			return { .header = h, .spec = spec };
		}
	}
	return HEADER_NOT_FOUND~;
}

fn FixupPlanResult plan_packet_fixups(PacketConstructor packet, Registry* registry, char[] buffer, usz packet_len, FixupOptions options = {}) {
	FixupPlanResult result;
	result.plan.packet_len = packet_len;
	List{String} errors;
	errors.tinit();

	if (buffer.len < packet_len) {
		errors.push(string::tformat("buffer has %d bytes but packet length is %d bytes", buffer.len, packet_len));
		result.errors = errors.to_tarray();
		return result;
	}

	char[] payload = buffer[:packet_len];

	HeaderRef? ip = find_header_ref(packet, registry, "IP");
	if (try ip) {
		if (packet_len < ip.header.offset + 20) {
			errors.push("IPv4 header extends beyond packet length");
		}
		else {
			usz ihl_bytes = (usz)(read_u8(payload, ip.header.offset) & 0x0f) * 4;
			if (ihl_bytes < 20 || ip.header.offset + ihl_bytes > packet_len) {
				errors.push(string::tformat("invalid IPv4 IHL %d bytes", ihl_bytes));
			}
			else {
				usz ip_len = packet_len - ip.header.offset;
				if (ip_len > 0xffff) {
					errors.push(string::tformat("IPv4 packet length %d exceeds 16 bits", ip_len));
				}

				result.plan.has_ipv4 = true;
				result.plan.ipv4 = { .offset = ip.header.offset, .header_len = ihl_bytes, .checksum = options.ipv4_checksum };
				if (options.ipv4_checksum == FixupMode.HARDWARE_OFFLOAD) {
					result.plan.offload.ipv4_checksum = true;
					result.plan.offload.layer3 = OffloadLayer3.IPV4;
					result.plan.offload.l2_len = ip.header.offset;
					result.plan.offload.l3_len = ihl_bytes;
				}
			}
		}
	}

	HeaderRef? ipv6 = find_header_ref(packet, registry, "IPv6");
	if (try ipv6) {
		usz ipv6_header_len = 40;
		if (packet_len < ipv6.header.offset + ipv6_header_len) {
			errors.push("IPv6 header extends beyond packet length");
		}
		else {
			usz payload_len = packet_len - ipv6.header.offset - ipv6_header_len;
			if (payload_len > 0xffff) {
				errors.push(string::tformat("IPv6 payload length %d exceeds 16 bits", payload_len));
			}
			result.plan.has_ipv6 = true;
			result.plan.ipv6 = { .offset = ipv6.header.offset, .header_len = ipv6_header_len };
		}
	}

	HeaderRef? udp = find_header_ref(packet, registry, "UDP");
	if (try udp) {
		if (packet_len < udp.header.offset + 8) {
			errors.push("UDP header extends beyond packet length");
		}
		else {
			usz udp_len = packet_len - udp.header.offset;
			if (udp_len > 0xffff) {
				errors.push(string::tformat("UDP length %d exceeds 16 bits", udp_len));
			}

			result.plan.has_udp = true;
			result.plan.udp = { .offset = udp.header.offset, .checksum = options.udp_checksum };
			if (options.udp_checksum != FixupMode.DISABLED) {
				bool has_pseudo_header = false;
				if (result.plan.has_ipv4) {
					result.plan.offload.l2_len = result.plan.ipv4.offset;
					result.plan.offload.l3_len = result.plan.ipv4.header_len;
					result.plan.offload.l4_len = 8;
					result.plan.offload.layer3 = OffloadLayer3.IPV4;
					has_pseudo_header = true;
				}
				else if (result.plan.has_ipv6) {
					result.plan.offload.l2_len = result.plan.ipv6.offset;
					result.plan.offload.l3_len = result.plan.ipv6.header_len;
					result.plan.offload.l4_len = 8;
					result.plan.offload.layer3 = OffloadLayer3.IPV6;
					has_pseudo_header = true;
				}
				else {
					errors.push("UDP checksum requires IPv4 or IPv6 header");
				}

				if (has_pseudo_header && options.udp_checksum == FixupMode.HARDWARE_OFFLOAD) {
					result.plan.offload.udp_checksum = true;
				}
			}
		}
	}

	HeaderRef? tcp = find_header_ref(packet, registry, "TCP");
	if (try tcp) {
		if (packet_len < tcp.header.offset + 20) {
			errors.push("TCP header extends beyond packet length");
		}
		else {
			usz tcp_len = packet_len - tcp.header.offset;
			usz tcp_header_len = (usz)(read_u8(payload, tcp.header.offset + 12) >> 4) * 4;
			if (tcp_header_len < 20 || tcp_header_len > tcp_len) {
				errors.push(string::tformat("invalid TCP header length %d bytes", tcp_header_len));
			}

			result.plan.has_tcp = true;
			result.plan.tcp = { .offset = tcp.header.offset, .header_len = tcp_header_len, .checksum = options.tcp_checksum };
			if (options.tcp_checksum != FixupMode.DISABLED) {
				bool has_pseudo_header = false;
				if (result.plan.has_ipv4) {
					result.plan.offload.l2_len = result.plan.ipv4.offset;
					result.plan.offload.l3_len = result.plan.ipv4.header_len;
					result.plan.offload.l4_len = tcp_header_len;
					result.plan.offload.layer3 = OffloadLayer3.IPV4;
					has_pseudo_header = true;
				}
				else if (result.plan.has_ipv6) {
					result.plan.offload.l2_len = result.plan.ipv6.offset;
					result.plan.offload.l3_len = result.plan.ipv6.header_len;
					result.plan.offload.l4_len = tcp_header_len;
					result.plan.offload.layer3 = OffloadLayer3.IPV6;
					has_pseudo_header = true;
				}
				else {
					errors.push("TCP checksum requires IPv4 or IPv6 header");
				}

				if (has_pseudo_header && options.tcp_checksum == FixupMode.HARDWARE_OFFLOAD) {
					result.plan.offload.tcp_checksum = true;
				}
			}
		}
	}

	HeaderRef? icmp = find_header_ref(packet, registry, "ICMP");
	if (try icmp) {
		if (options.icmp_checksum != FixupMode.DISABLED) {
			if (packet_len < icmp.header.offset + 4) {
				errors.push("ICMP header extends beyond packet length");
			}
			else if (options.icmp_checksum == FixupMode.HARDWARE_OFFLOAD) {
				errors.push("ICMP hardware checksum offload is not supported");
			}
			else {
				result.plan.has_icmp = true;
				result.plan.icmp = { .offset = icmp.header.offset, .checksum = options.icmp_checksum };
			}
		}
	}

	result.errors = errors.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

fn FixupResult apply_fixup_plan(char[] buffer, PacketFixupPlan plan) {
	FixupResult result;
	result.offload = plan.offload;
	List{String} errors;
	errors.tinit();

	if (buffer.len < plan.packet_len) {
		errors.push(string::tformat("buffer has %d bytes but packet length is %d bytes", buffer.len, plan.packet_len));
		result.errors = errors.to_tarray();
		return result;
	}

	char[] payload = buffer[:plan.packet_len];

	if (plan.has_ipv4) {
		Ipv4Fixup ipv4 = plan.ipv4;
		write_u16(payload, ipv4.offset + 2, (ushort)(plan.packet_len - ipv4.offset));
		if (ipv4.checksum != FixupMode.DISABLED) {
			write_u16(payload, ipv4.offset + 10, 0);
			if (ipv4.checksum == FixupMode.SOFTWARE) {
				write_u16(payload, ipv4.offset + 10, internet_checksum(checksum_sum(payload[ipv4.offset : ipv4.header_len])));
			}
		}
	}

	if (plan.has_ipv6) {
		Ipv6Fixup ipv6 = plan.ipv6;
		usz payload_len = plan.packet_len - ipv6.offset - ipv6.header_len;
		write_u16(payload, ipv6.offset + 4, (ushort)payload_len);
	}

	if (plan.has_udp) {
		UdpFixup udp = plan.udp;
		usz udp_len = plan.packet_len - udp.offset;
		write_u16(payload, udp.offset + 4, (ushort)udp_len);
		if (udp.checksum != FixupMode.DISABLED) {
			write_u16(payload, udp.offset + 6, 0);

			uint pseudo_sum = 0;
			bool has_pseudo_header = false;
			if (plan.has_ipv4) {
				pseudo_sum = ipv4_pseudo_sum(payload, plan.ipv4.offset, UDP_PROTOCOL, (ushort)udp_len);
				has_pseudo_header = true;
			}
			else if (plan.has_ipv6) {
				pseudo_sum = ipv6_pseudo_sum(payload, plan.ipv6.offset, UDP_PROTOCOL, (uint)udp_len);
				has_pseudo_header = true;
			}

			if (!has_pseudo_header) {
				errors.push("UDP checksum requires IPv4 or IPv6 header");
			}
			else if (udp.checksum == FixupMode.SOFTWARE) {
				ushort checksum = internet_checksum(pseudo_sum + checksum_sum(payload[udp.offset : udp_len]));
				if (checksum == 0) checksum = 0xffff;
				write_u16(payload, udp.offset + 6, checksum);
			}
			else if (udp.checksum == FixupMode.HARDWARE_OFFLOAD) {
				write_u16(payload, udp.offset + 6, fold_checksum(pseudo_sum));
			}
		}
	}

	if (plan.has_tcp && plan.tcp.checksum != FixupMode.DISABLED) {
		TcpFixup tcp = plan.tcp;
		write_u16(payload, tcp.offset + 16, 0);
		usz tcp_len = plan.packet_len - tcp.offset;

		uint pseudo_sum = 0;
		bool has_pseudo_header = false;
		if (plan.has_ipv4) {
			pseudo_sum = ipv4_pseudo_sum(payload, plan.ipv4.offset, TCP_PROTOCOL, (ushort)tcp_len);
			has_pseudo_header = true;
		}
		else if (plan.has_ipv6) {
			pseudo_sum = ipv6_pseudo_sum(payload, plan.ipv6.offset, TCP_PROTOCOL, (uint)tcp_len);
			has_pseudo_header = true;
		}

		if (!has_pseudo_header) {
			errors.push("TCP checksum requires IPv4 or IPv6 header");
		}
		else if (tcp.checksum == FixupMode.SOFTWARE) {
			write_u16(payload, tcp.offset + 16, internet_checksum(pseudo_sum + checksum_sum(payload[tcp.offset : tcp_len])));
		}
		else if (tcp.checksum == FixupMode.HARDWARE_OFFLOAD) {
			write_u16(payload, tcp.offset + 16, fold_checksum(pseudo_sum));
		}
	}

	if (plan.has_icmp && plan.icmp.checksum != FixupMode.DISABLED) {
		write_u16(payload, plan.icmp.offset + 2, 0);
		write_u16(payload, plan.icmp.offset + 2,
			internet_checksum(checksum_sum(payload[plan.icmp.offset : plan.packet_len - plan.icmp.offset])));
	}

	result.errors = errors.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

fn FixupResult fixup_packet(PacketConstructor packet, Registry* registry, char[] buffer, usz packet_len, FixupOptions options = {}) {
	FixupPlanResult plan = plan_packet_fixups(packet, registry, buffer, packet_len, options);
	if (!plan.ok) {
		return { .ok = false, .errors = plan.errors, .offload = plan.plan.offload };
	}
	return apply_fixup_plan(buffer, plan.plan);
}
