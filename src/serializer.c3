module flowforge::serializer;
import flowforge::constructor;
import flowforge::cvalue;
import flowforge::registry;
import flowforge::value;
import std::collections::list;
import std::collections::maybe;
import std::collections::result;
import std::math::random;

faultdef SERIALIZE_ERR, NO_MODIFIER, OUT_OF_RANGE, HEADER_NOT_FOUND;

const char TCP_PROTOCOL = 6;
const char UDP_PROTOCOL = 17;

enum ModifierValueKind {
	UINT_RANGES,
	IPV4_RANGES,
	IPV6_RANGES,
}

enum ModifierPatchKind {
	BITS,
	U8,
	U16_BE,
	U32_BE,
	IPV4,
	IPV6,
}

enum RangeTraversalKind {
	SEQUENTIAL,
	STRIDED,
	RANDOM,
}

struct RangeTraversal {
	RangeTraversalKind kind;
	ulong step;
	ulong cycle_length;
}

struct UIntPatchRange {
	ulong first;
	ulong count;
	uint128 length;
	RangeTraversal traversal;
}

struct IPv4PatchRange {
	uint first;
	ulong count;
	uint128 length;
	RangeTraversal traversal;
}

struct IPv6PatchRange {
	IPv6 first;
	ulong count;
	uint128 length;
	bool full_domain;
	RangeTraversal traversal;
}

struct PayloadFieldModifier {
	String protocol;
	String field;
	usz bit_offset;
	usz bit_width;
	usz byte_offset;
	ulong value_count;
	ModifierValueKind values_kind;
	ModifierPatchKind patch_kind;
	union {
		UIntPatchRange[] uint_ranges;
		IPv4PatchRange[] ipv4_ranges;
		IPv6PatchRange[] ipv6_ranges;
	}
}

struct SerializeResult {
	bool ok;
	String[] errors;
	char[] payload;
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
	bool outer_ipv4_checksum;
	bool tcp_checksum;
	bool udp_checksum;
	bool tunnel_vxlan;
	usz l2_len;
	usz l3_len;
	usz l4_len;
	usz outer_l2_len;
	usz outer_l3_len;
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

// A single packet can carry several layer-3/layer-4 headers at once (e.g. a
// VXLAN packet has an outer IPv4/UDP plus an inner IPv4/TCP). Each fixup is
// therefore tracked independently — mirroring the `std::optional` fields of the
// C++ plan — so that, for instance, the outer UDP length is still written even
// when an inner TCP header is present.
struct PacketFixupPlan {
	bool vxlan_tunnel;
	Maybe{Ipv4Fixup} outer_ipv4;
	Maybe{Ipv6Fixup} outer_ipv6;
	Maybe{UdpFixup} outer_udp;
	Maybe{Ipv4Fixup} ipv4;
	Maybe{Ipv6Fixup} ipv6;
	Maybe{UdpFixup} udp;
	Maybe{TcpFixup} tcp;
	Maybe{IcmpFixup} icmp;
	PacketOffloadRequest offload;
	Maybe{uint} udp_ipv4_pseudo_base;
	Maybe{uint} tcp_ipv4_pseudo_base;
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

fn void write_u32(char[] payload, usz offset, uint value) {
	payload[offset] = (char)(value >> 24);
	payload[offset + 1] = (char)((value >> 16) & 0xff);
	payload[offset + 2] = (char)((value >> 8) & 0xff);
	payload[offset + 3] = (char)(value & 0xff);
}

// --- range counting / addressing --------------------------------------

fn ulong saturated_add_count(ulong left, ulong right) {
	if (ulong::max - left < right) return ulong::max;
	return left + right;
}

fn ulong saturated_u128_count(uint128 count) {
	return count >= (uint128)ulong::max ? ulong::max : (ulong)count;
}

fn ulong range_step(Maybe{ulong} step) {
	return step.has_value ? step.value : 1;
}

fn ulong gcd_u128_ulong(uint128 left, ulong right) {
	uint128 a = left;
	uint128 b = (uint128)right;
	while (b != 0) {
		uint128 remainder = a % b;
		a = b;
		b = remainder;
	}
	return (ulong)a;
}

fn RangeTraversal make_range_traversal(uint128 length, bool full_domain, Maybe{ulong} requested_step, bool requested_random) {
	if (requested_random) return { .kind = RangeTraversalKind.RANDOM };
	ulong step = range_step(requested_step);
	if (step == 1) return { .kind = RangeTraversalKind.SEQUENTIAL };
	ulong cycle_length = ulong::max;
	if (!full_domain) {
		ulong divisor = gcd_u128_ulong(length, step);
		cycle_length = saturated_u128_count(length / (uint128)divisor);
	}
	return {
		.kind = RangeTraversalKind.STRIDED,
		.step = step,
		.cycle_length = cycle_length,
	};
}

<* DPDK's generator is already per-lcore. The stdlib fallback uses the same
   thread-local SFC64 generator that backs random::rnd(), but reads all 64 bits
   directly instead of converting through rnd()'s 53-bit double result. *>

tlocal random::Sfc64Random range_random_state @private @feat(!DPDK);
tlocal bool range_random_initialized @private @feat(!DPDK);

fn ulong range_random_u64() @private @feat(!DPDK) {
	if (!range_random_initialized) {
		random::seed_entropy(&range_random_state);
		range_random_initialized = true;
	}
	return range_random_state.next_long();
}

fn ulong random_below_u64(ulong upper_bound) {
	if (upper_bound == 0) return range_random_u64();
	if (upper_bound == 1) return 0;
	ulong mask = ulong::max >> (upper_bound - 1).clz();
	while (true) {
		ulong candidate = range_random_u64() & mask;
		if (candidate < upper_bound) return candidate;
	}
}

fn uint128 random_below_u128(uint128 upper_bound, bool full_domain) {
	if (full_domain) {
		return (uint128)range_random_u64() << 64 | (uint128)range_random_u64();
	}
	if (upper_bound <= (uint128)ulong::max) {
		return (uint128)random_below_u64((ulong)upper_bound);
	}
	if (upper_bound == (uint128)ulong::max + 1) return (uint128)range_random_u64();
	uint128 threshold = ((uint128)0 - upper_bound) % upper_bound;
	while (true) {
		uint128 candidate = (uint128)range_random_u64() << 64 | (uint128)range_random_u64();
		if (candidate >= threshold) return candidate % upper_bound;
	}
}

fn ulong total_uint_patch_count(UIntPatchRange[] ranges) {
	ulong total = 0;
	foreach (range : ranges) total = saturated_add_count(total, range.count);
	return total;
}

fn ulong total_ipv4_patch_count(IPv4PatchRange[] ranges) {
	ulong total = 0;
	foreach (range : ranges) total = saturated_add_count(total, range.count);
	return total;
}

fn ulong total_ipv6_patch_count(IPv6PatchRange[] ranges) {
	ulong total = 0;
	foreach (range : ranges) total = saturated_add_count(total, range.count);
	return total;
}

struct UIntRangeAt {
	UIntPatchRange range;
	ulong offset;
}

struct Ipv4RangeAt {
	IPv4PatchRange range;
	ulong offset;
}

struct Ipv6RangeAt {
	IPv6PatchRange range;
	ulong offset;
}

fn UIntRangeAt? uint_range_at_index(UIntPatchRange[] ranges, ulong value_index) {
	foreach (r : ranges) {
		if (value_index < r.count) return { .range = r, .offset = value_index };
		value_index -= r.count;
	}
	return OUT_OF_RANGE~;
}

fn Ipv4RangeAt? ipv4_range_at_index(IPv4PatchRange[] ranges, ulong value_index) {
	foreach (r : ranges) {
		if (value_index < r.count) return { .range = r, .offset = value_index };
		value_index -= r.count;
	}
	return OUT_OF_RANGE~;
}

fn Ipv6RangeAt? ipv6_range_at_index(IPv6PatchRange[] ranges, ulong value_index) {
	foreach (r : ranges) {
		if (value_index < r.count) return { .range = r, .offset = value_index };
		value_index -= r.count;
	}
	return OUT_OF_RANGE~;
}

fn uint128 range_traversal_offset(ulong index, uint128 length, bool full_domain, RangeTraversal traversal) {
	switch (traversal.kind) {
		case SEQUENTIAL:
			return (uint128)index;
		case STRIDED:
			ulong group = index / traversal.cycle_length;
			ulong position = index % traversal.cycle_length;
			uint128 offset = (uint128)group + (uint128)position * (uint128)traversal.step;
			return full_domain ? offset : offset % length;
		case RANDOM:
			return random_below_u128(length, full_domain);
	}
}

fn IPv6 add_ipv6_traversal_offset(IPv6 ip, ulong index, IPv6PatchRange range) {
	uint128 offset = range_traversal_offset(index, range.length, range.full_domain, range.traversal);
	uint128 value = cvalue::ipv6_to_u128(ip) + offset;
	return cvalue::ipv6_from_u128(value);
}

// --- PayloadFieldModifier ----------------------------------------------

fn ModifierPatchKind patch_kind_for(ModifierValueKind values_kind, usz bit_offset, usz bit_width) {
	if (values_kind == ModifierValueKind.IPV6_RANGES && bit_width == 128) return ModifierPatchKind.IPV6;
	if (bit_offset % 8 != 0) return ModifierPatchKind.BITS;
	switch (values_kind) {
		case UINT_RANGES:
			if (bit_width == 8) return ModifierPatchKind.U8;
			if (bit_width == 16) return ModifierPatchKind.U16_BE;
			if (bit_width == 32) return ModifierPatchKind.U32_BE;
			return ModifierPatchKind.BITS;
		case IPV4_RANGES:
			return bit_width == 32 ? ModifierPatchKind.IPV4 : ModifierPatchKind.BITS;
		case IPV6_RANGES:
			return bit_width == 128 ? ModifierPatchKind.IPV6 : ModifierPatchKind.BITS;
	}
}

fn void write_modifier_value(PayloadFieldModifier* modifier, char[] payload, ulong value, IPv6 ipv6 = {}) {
	switch (modifier.patch_kind) {
		case BITS:
			write_bits(payload, modifier.bit_offset, modifier.bit_width, value);
			return;
		case U8:
			payload[modifier.byte_offset] = (char)value;
			return;
		case U16_BE:
			write_u16(payload, modifier.byte_offset, (ushort)value);
			return;
		case U32_BE:
		case IPV4:
			write_u32(payload, modifier.byte_offset, (uint)value);
			return;
		case IPV6:
			write_bytes(payload, modifier.bit_offset, ipv6.bytes[..]);
			return;
	}
}

<* Returns the actual value written, including the sampled value for random
   traversal. IPv6 addresses use their network-order numeric representation. *>
fn Result{uint128, String} PayloadFieldModifier.apply(&self, char[] payload, ulong value_index) {
	if (self.bit_width > usz::max - self.bit_offset || (self.bit_offset + self.bit_width + 7) / 8 > payload.len) {
		return result::err(string::tformat("payload is too small for modifier '%s.%s'", self.protocol, self.field));
	}

	switch (self.values_kind) {
		case UINT_RANGES:
			UIntRangeAt? found = uint_range_at_index(self.uint_ranges, value_index);
			if (catch found) {
				return result::err(string::tformat("value index %d is out of range for modifier '%s.%s'", value_index, self.protocol, self.field));
			}
			uint128 offset = range_traversal_offset(found.offset, found.range.length, false, found.range.traversal);
			ulong applied_value = found.range.first + (ulong)offset;
			write_modifier_value(self, payload, applied_value);
			return result::ok((uint128)applied_value);
		case IPV4_RANGES:
			Ipv4RangeAt? found = ipv4_range_at_index(self.ipv4_ranges, value_index);
			if (catch found) {
				return result::err(string::tformat("value index %d is out of range for modifier '%s.%s'", value_index, self.protocol, self.field));
			}
			uint128 offset = range_traversal_offset(found.offset, found.range.length, false, found.range.traversal);
			uint applied_value = found.range.first + (uint)offset;
			write_modifier_value(self, payload, (ulong)applied_value);
			return result::ok((uint128)applied_value);
		case IPV6_RANGES:
			Ipv6RangeAt? found = ipv6_range_at_index(self.ipv6_ranges, value_index);
			if (catch found) {
				return result::err(string::tformat("value index %d is out of range for modifier '%s.%s'", value_index, self.protocol, self.field));
			}
			IPv6 ip = add_ipv6_traversal_offset(found.range.first, found.offset, found.range);
			write_modifier_value(self, payload, 0, ip);
			return result::ok(cvalue::ipv6_to_u128(ip));
	}
}

fn uint ipv4_replace_delta(uint old_value, uint new_value) {
	return (uint)((new_value >> 16) & 0xffff) +
		(uint)(new_value & 0xffff) +
		(uint)(~(old_value >> 16) & 0xffff) +
		(uint)(~old_value & 0xffff);
}

<* Computes the change from the base IPv4 address using the value returned by
   apply(). Never samples random traversal again or reads the packet buffer. *>
fn uint PayloadFieldModifier.ipv4_pseudo_delta(&self, PacketFixupPlan plan, uint128 applied_value) {
	if (self.patch_kind != ModifierPatchKind.IPV4) return 0;
	if (!plan.ipv4.has_value) return 0;
	usz ip_offset = plan.ipv4.value.offset;
	if (self.byte_offset != ip_offset + 12 && self.byte_offset != ip_offset + 16) return 0;

	return ipv4_replace_delta(self.ipv4_ranges[0].first, (uint)applied_value);
}

fn UIntPatchRange[] make_uint_patch_ranges(UIntRange[] src) {
	UIntPatchRange[] dst = mem::temp_array(UIntPatchRange, src.len);
	foreach (i, r : src) {
		uint128 length = (uint128)r.last - (uint128)r.first + 1;
		dst[i] = {
			.first = r.first,
			.count = saturated_u128_count(length),
			.length = length,
			.traversal = make_range_traversal(length, false, r.step, r.random),
		};
	}
	return dst;
}

fn IPv4PatchRange[] make_ipv4_patch_ranges(IPv4Range[] src) {
	IPv4PatchRange[] dst = mem::temp_array(IPv4PatchRange, src.len);
	foreach (i, r : src) {
		uint128 length = (uint128)cvalue::ipv4_to_u32(r.last) -
			(uint128)cvalue::ipv4_to_u32(r.first) + 1;
		dst[i] = {
			.first = cvalue::ipv4_to_u32(r.first),
			.count = (ulong)length,
			.length = length,
			.traversal = make_range_traversal(length, false, r.step, r.random),
		};
	}
	return dst;
}

fn IPv6PatchRange[] make_ipv6_patch_ranges(IPv6Range[] src) {
	IPv6PatchRange[] dst = mem::temp_array(IPv6PatchRange, src.len);
	foreach (i, r : src) {
		uint128 difference = cvalue::ipv6_to_u128(r.last) - cvalue::ipv6_to_u128(r.first);
		bool full_domain = difference == uint128::max;
		uint128 length = full_domain ? 0 : difference + 1;
		dst[i] = {
			.first = r.first,
			.count = full_domain ? ulong::max : saturated_u128_count(length),
			.length = length,
			.full_domain = full_domain,
			.traversal = make_range_traversal(length, full_domain, r.step, r.random),
		};
	}
	return dst;
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

<* @param [&in] registry : `read-only protocol definitions` *>
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

<* @param [&in] registry : `read-only protocol definitions` *>
fn usz packet_option_bit_width(OptionConstructor option, Registry* registry) {
	if (option.value_kind != AttrValueKind.PACKET) return 0;
	usz bit_width = packet_bit_width(option.packet_value, registry);
	return ((bit_width + 31) / 32) * 32;
}

<* @param [&in] registry : `read-only protocol definitions` *>
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

fn Result{ulong, String} first_integer_value(ConstructorValue value, String field_name) {
	if (value.kind == ConstructorValueKind.UINT) return result::ok(value.uint_val);
	if (value.kind == ConstructorValueKind.UINT_RANGES) {
		if (value.uint_ranges_val.len == 0) {
			return result::err(string::tformat("field '%s' has an empty integer range list", field_name));
		}
		return result::ok(value.uint_ranges_val[0].first);
	}
	return result::err(string::tformat("field '%s' is not an integer value", field_name));
}

fn Result{IPv4, String} first_ipv4_value(ConstructorValue value, String field_name) {
	if (value.kind == ConstructorValueKind.IPV4) return result::ok(value.ipv4_val);
	if (value.kind == ConstructorValueKind.IPV4_RANGE) return result::ok(value.ipv4_range_val.first);
	if (value.kind == ConstructorValueKind.IPV4_RANGES) {
		if (value.ipv4_ranges_val.len == 0) {
			return result::err(string::tformat("field '%s' has an empty ipv4 range list", field_name));
		}
		return result::ok(value.ipv4_ranges_val[0].first);
	}
	return result::err(string::tformat("field '%s' is not an ipv4 value", field_name));
}

fn Result{IPv6, String} first_ipv6_value(ConstructorValue value, String field_name) {
	if (value.kind == ConstructorValueKind.IPV6) return result::ok(value.ipv6_val);
	if (value.kind == ConstructorValueKind.IPV6_RANGE) return result::ok(value.ipv6_range_val.first);
	if (value.kind == ConstructorValueKind.IPV6_RANGES) {
		if (value.ipv6_ranges_val.len == 0) {
			return result::err(string::tformat("field '%s' has an empty ipv6 range list", field_name));
		}
		return result::ok(value.ipv6_ranges_val[0].first);
	}
	return result::err(string::tformat("field '%s' is not an ipv6 value", field_name));
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
		Result{IPv4, String} ip = first_ipv4_value(field.value, field.name);
		if (!ip.is_ok) {
			errors.push(ip.error);
			return false;
		}
		write_bytes(payload, bit_offset, ip.value.bytes[..]);
		return true;
	}
	if (type == "ipv6" || type == "ipv6_range" || type == "ipv6_ranges") {
		Result{IPv6, String} ip = first_ipv6_value(field.value, field.name);
		if (!ip.is_ok) {
			errors.push(ip.error);
			return false;
		}
		write_bytes(payload, bit_offset, ip.value.bytes[..]);
		return true;
	}

	Result{ulong, String} integer = first_integer_value(field.value, field.name);
	if (!integer.is_ok) {
		errors.push(integer.error);
		return false;
	}
	write_bits(payload, bit_offset, spec.bit_width, integer.value);
	return true;
}

fn PayloadFieldModifier? make_modifier(HeaderConstructor header, FieldSpec* spec, FieldConstructor field, usz bit_offset, List{String}* errors) {
	PayloadFieldModifier modifier;
	modifier.protocol = header.protocol;
	modifier.field = field.name;
	modifier.bit_offset = bit_offset;
	modifier.bit_width = spec.bit_width;
	modifier.byte_offset = bit_offset / 8;

	switch (field.value.kind) {
		case IPV4_RANGE:
			IPv4Range[] one = mem::temp_array(IPv4Range, 1);
			one[0] = field.value.ipv4_range_val;
			IPv4PatchRange[] patch_ranges = make_ipv4_patch_ranges(one);
			ulong count = patch_ranges[0].count;
			if (count <= 1) return NO_MODIFIER~;
			modifier.values_kind = ModifierValueKind.IPV4_RANGES;
			modifier.patch_kind = patch_kind_for(modifier.values_kind, bit_offset, spec.bit_width);
			modifier.ipv4_ranges = patch_ranges;
			modifier.value_count = count;
			return modifier;
		case IPV6_RANGE:
			IPv6Range[] one = mem::temp_array(IPv6Range, 1);
			one[0] = field.value.ipv6_range_val;
			IPv6PatchRange[] patch_ranges = make_ipv6_patch_ranges(one);
			ulong count = patch_ranges[0].count;
			if (count <= 1) return NO_MODIFIER~;
			modifier.values_kind = ModifierValueKind.IPV6_RANGES;
			modifier.patch_kind = patch_kind_for(modifier.values_kind, bit_offset, spec.bit_width);
			modifier.ipv6_ranges = patch_ranges;
			modifier.value_count = count;
			return modifier;
		case UINT_RANGES:
			UIntRange[] ranges = field.value.uint_ranges_val;
			if (ranges.len == 0) {
				errors.push(string::tformat("field '%s' has an empty integer range list", field.name));
				return NO_MODIFIER~;
			}
			UIntPatchRange[] patch_ranges = make_uint_patch_ranges(ranges);
			ulong count = total_uint_patch_count(patch_ranges);
			if (count <= 1) return NO_MODIFIER~;
			modifier.values_kind = ModifierValueKind.UINT_RANGES;
			modifier.patch_kind = patch_kind_for(modifier.values_kind, bit_offset, spec.bit_width);
			modifier.uint_ranges = patch_ranges;
			modifier.value_count = count;
			return modifier;
		case IPV4_RANGES:
			IPv4Range[] ranges4 = field.value.ipv4_ranges_val;
			if (ranges4.len == 0) {
				errors.push(string::tformat("field '%s' has an empty ipv4 range list", field.name));
				return NO_MODIFIER~;
			}
			IPv4PatchRange[] patch_ranges = make_ipv4_patch_ranges(ranges4);
			ulong count = total_ipv4_patch_count(patch_ranges);
			if (count <= 1) return NO_MODIFIER~;
			modifier.values_kind = ModifierValueKind.IPV4_RANGES;
			modifier.patch_kind = patch_kind_for(modifier.values_kind, bit_offset, spec.bit_width);
			modifier.ipv4_ranges = patch_ranges;
			modifier.value_count = count;
			return modifier;
		case IPV6_RANGES:
			IPv6Range[] ranges6 = field.value.ipv6_ranges_val;
			if (ranges6.len == 0) {
				errors.push(string::tformat("field '%s' has an empty ipv6 range list", field.name));
				return NO_MODIFIER~;
			}
			IPv6PatchRange[] patch_ranges = make_ipv6_patch_ranges(ranges6);
			ulong count = total_ipv6_patch_count(patch_ranges);
			if (count <= 1) return NO_MODIFIER~;
			modifier.values_kind = ModifierValueKind.IPV6_RANGES;
			modifier.patch_kind = patch_kind_for(modifier.values_kind, bit_offset, spec.bit_width);
			modifier.ipv6_ranges = patch_ranges;
			modifier.value_count = count;
			return modifier;
		default:
			return NO_MODIFIER~;
	}
}

<* @param [&in] registry : `read-only protocol definitions` *>
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

<* @param [&in] registry : `read-only protocol definitions` *>
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

	usz written = bit_width / 8;
	if (output.len < written) {
		errors.push(string::tformat("output buffer has %d bytes but packet requires %d bytes", output.len, written));
		result.errors = errors.to_tarray();
		return result;
	}

	mem::clear(output.ptr, (sz)written);

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

	result.payload = output[:written];
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

<* @param [&in] registry : `read-only protocol definitions` *>
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

<* Finds the last matching header that starts before `before_offset`. This is
   used to identify outer headers in tunnel packets. *>
fn HeaderRef? find_header_ref_before(PacketConstructor packet, Registry* registry, String protocol, usz before_offset) {
	HeaderRef found;
	bool has_found = false;
	foreach (&h : packet) {
		if (h.offset >= before_offset) continue;
		if (h.protocol == protocol) {
			HeaderSpec*? spec = registry.find_header(h.protocol);
			if (catch spec) return HEADER_NOT_FOUND~;
			found = { .header = h, .spec = spec };
			has_found = true;
		}
	}
	if (has_found) return found;
	return HEADER_NOT_FOUND~;
}

<* Finds the first matching header that starts after `after_offset`. This is
   used to identify inner headers in tunnel packets. *>
fn HeaderRef? find_header_ref_after(PacketConstructor packet, Registry* registry, String protocol, usz after_offset) {
	foreach (&h : packet) {
		if (h.offset <= after_offset) continue;
		if (h.protocol == protocol) {
			HeaderSpec*? spec = registry.find_header(h.protocol);
			if (catch spec) return HEADER_NOT_FOUND~;
			return { .header = h, .spec = spec };
		}
	}
	return HEADER_NOT_FOUND~;
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn FixupPlanResult plan_packet_fixups(PacketConstructor packet, Registry* registry, char[] payload, FixupOptions options = {}) {
	FixupPlanResult result;
	List{String} errors;
	errors.tinit();

	HeaderRef? vxlan = find_header_ref(packet, registry, "VXLAN");
	if (try vxlan) {
		usz vxlan_offset = vxlan.header.offset;
		result.plan.vxlan_tunnel = true;
		result.plan.offload.tunnel_vxlan = true;

		HeaderRef? outer_ip = find_header_ref_before(packet, registry, "IP", vxlan_offset);
		if (try outer_ip) {
			if (payload.len < outer_ip.header.offset + 20) {
				errors.push("outer IPv4 header extends beyond packet length");
			}
			else {
				usz ihl_bytes = (usz)(read_u8(payload, outer_ip.header.offset) & 0x0f) * 4;
				if (ihl_bytes < 20 || outer_ip.header.offset + ihl_bytes > payload.len) {
					errors.push(string::tformat("invalid outer IPv4 IHL %d bytes", ihl_bytes));
				}
				else {
					usz ip_len = payload.len - outer_ip.header.offset;
					if (ip_len > 0xffff) {
						errors.push(string::tformat("outer IPv4 packet length %d exceeds 16 bits", ip_len));
					}

					result.plan.outer_ipv4.set({ .offset = outer_ip.header.offset, .header_len = ihl_bytes, .checksum = options.ipv4_checksum });
					result.plan.offload.outer_l2_len = outer_ip.header.offset;
					result.plan.offload.outer_l3_len = ihl_bytes;
					if (options.ipv4_checksum == FixupMode.HARDWARE_OFFLOAD) {
						result.plan.offload.outer_ipv4_checksum = true;
					}
				}
			}
		}

		HeaderRef? outer_ipv6 = find_header_ref_before(packet, registry, "IPv6", vxlan_offset);
		if (try outer_ipv6) {
			usz ipv6_header_len = 40;
			if (payload.len < outer_ipv6.header.offset + ipv6_header_len) {
				errors.push("outer IPv6 header extends beyond packet length");
			}
			else {
				usz payload_len = payload.len - outer_ipv6.header.offset - ipv6_header_len;
				if (payload_len > 0xffff) {
					errors.push(string::tformat("outer IPv6 payload length %d exceeds 16 bits", payload_len));
				}
				result.plan.outer_ipv6.set({ .offset = outer_ipv6.header.offset, .header_len = ipv6_header_len });
				result.plan.offload.outer_l2_len = outer_ipv6.header.offset;
				result.plan.offload.outer_l3_len = ipv6_header_len;
			}
		}

		HeaderRef? outer_udp = find_header_ref_before(packet, registry, "UDP", vxlan_offset);
		if (try outer_udp) {
			if (payload.len < outer_udp.header.offset + 8) {
				errors.push("outer UDP header extends beyond packet length");
			}
			else {
				usz udp_len = payload.len - outer_udp.header.offset;
				if (udp_len > 0xffff) {
					errors.push(string::tformat("outer UDP length %d exceeds 16 bits", udp_len));
				}
				result.plan.outer_udp.set({ .offset = outer_udp.header.offset, .checksum = FixupMode.DISABLED });
			}
		}

		HeaderRef? inner_ip = find_header_ref_after(packet, registry, "IP", vxlan_offset);
		if (try inner_ip) {
			if (payload.len < inner_ip.header.offset + 20) {
				errors.push("inner IPv4 header extends beyond packet length");
			}
			else {
				usz ihl_bytes = (usz)(read_u8(payload, inner_ip.header.offset) & 0x0f) * 4;
				if (ihl_bytes < 20 || inner_ip.header.offset + ihl_bytes > payload.len) {
					errors.push(string::tformat("invalid inner IPv4 IHL %d bytes", ihl_bytes));
				}
				else {
					usz ip_len = payload.len - inner_ip.header.offset;
					if (ip_len > 0xffff) {
						errors.push(string::tformat("inner IPv4 packet length %d exceeds 16 bits", ip_len));
					}
					result.plan.ipv4.set({ .offset = inner_ip.header.offset, .header_len = ihl_bytes, .checksum = options.ipv4_checksum });
					result.plan.offload.layer3 = OffloadLayer3.IPV4;
					result.plan.offload.l3_len = ihl_bytes;
					if (options.ipv4_checksum == FixupMode.HARDWARE_OFFLOAD) {
						result.plan.offload.ipv4_checksum = true;
					}
					usz tunnel_prefix = result.plan.offload.outer_l2_len + result.plan.offload.outer_l3_len;
					if (inner_ip.header.offset >= tunnel_prefix) {
						result.plan.offload.l2_len = inner_ip.header.offset - tunnel_prefix;
					}
				}
			}
		}

		HeaderRef? inner_ipv6 = find_header_ref_after(packet, registry, "IPv6", vxlan_offset);
		if (try inner_ipv6) {
			usz ipv6_header_len = 40;
			if (payload.len < inner_ipv6.header.offset + ipv6_header_len) {
				errors.push("inner IPv6 header extends beyond packet length");
			}
			else {
				usz payload_len = payload.len - inner_ipv6.header.offset - ipv6_header_len;
				if (payload_len > 0xffff) {
					errors.push(string::tformat("inner IPv6 payload length %d exceeds 16 bits", payload_len));
				}
				result.plan.ipv6.set({ .offset = inner_ipv6.header.offset, .header_len = ipv6_header_len });
				result.plan.offload.layer3 = OffloadLayer3.IPV6;
				result.plan.offload.l3_len = ipv6_header_len;
				usz tunnel_prefix = result.plan.offload.outer_l2_len + result.plan.offload.outer_l3_len;
				if (inner_ipv6.header.offset >= tunnel_prefix) {
					result.plan.offload.l2_len = inner_ipv6.header.offset - tunnel_prefix;
				}
			}
		}

		HeaderRef? inner_udp = find_header_ref_after(packet, registry, "UDP", vxlan_offset);
		if (try inner_udp) {
			if (payload.len < inner_udp.header.offset + 8) {
				errors.push("inner UDP header extends beyond packet length");
			}
			else {
				usz udp_len = payload.len - inner_udp.header.offset;
				if (udp_len > 0xffff) {
					errors.push(string::tformat("inner UDP length %d exceeds 16 bits", udp_len));
				}
				result.plan.udp.set({ .offset = inner_udp.header.offset, .checksum = options.udp_checksum });
				result.plan.offload.l4_len = 8;
				if (options.udp_checksum == FixupMode.HARDWARE_OFFLOAD) {
					result.plan.offload.udp_checksum = true;
				}
			}
		}

		HeaderRef? inner_tcp = find_header_ref_after(packet, registry, "TCP", vxlan_offset);
		if (try inner_tcp) {
			if (payload.len < inner_tcp.header.offset + 20) {
				errors.push("inner TCP header extends beyond packet length");
			}
			else {
				usz tcp_len = payload.len - inner_tcp.header.offset;
				usz tcp_header_len = (usz)(read_u8(payload, inner_tcp.header.offset + 12) >> 4) * 4;
				if (tcp_header_len < 20 || tcp_header_len > tcp_len) {
					errors.push(string::tformat("invalid inner TCP header length %d bytes", tcp_header_len));
				}
				result.plan.tcp.set({ .offset = inner_tcp.header.offset, .header_len = tcp_header_len, .checksum = options.tcp_checksum });
				result.plan.offload.l4_len = tcp_header_len;
				if (options.tcp_checksum == FixupMode.HARDWARE_OFFLOAD) {
					result.plan.offload.tcp_checksum = true;
				}
			}
		}

		HeaderRef? inner_icmp = find_header_ref_after(packet, registry, "ICMP", vxlan_offset);
		if (try inner_icmp) {
			if (options.icmp_checksum != FixupMode.DISABLED) {
				if (payload.len < inner_icmp.header.offset + 4) {
					errors.push("inner ICMP header extends beyond packet length");
				}
				else if (options.icmp_checksum == FixupMode.HARDWARE_OFFLOAD) {
					errors.push("ICMP hardware checksum offload is not supported");
				}
				else {
					result.plan.icmp.set({ .offset = inner_icmp.header.offset, .checksum = options.icmp_checksum });
				}
			}
		}

		populate_ipv4_pseudo_bases(payload, &result.plan);
		result.errors = errors.to_tarray();
		result.ok = errors.len() == 0;
		return result;
	}

	HeaderRef? ip = find_header_ref(packet, registry, "IP");
	if (try ip) {
		if (payload.len < ip.header.offset + 20) {
			errors.push("IPv4 header extends beyond packet length");
		}
		else {
			usz ihl_bytes = (usz)(read_u8(payload, ip.header.offset) & 0x0f) * 4;
			if (ihl_bytes < 20 || ip.header.offset + ihl_bytes > payload.len) {
				errors.push(string::tformat("invalid IPv4 IHL %d bytes", ihl_bytes));
			}
			else {
				usz ip_len = payload.len - ip.header.offset;
				if (ip_len > 0xffff) {
					errors.push(string::tformat("IPv4 packet length %d exceeds 16 bits", ip_len));
				}

				result.plan.ipv4.set({ .offset = ip.header.offset, .header_len = ihl_bytes, .checksum = options.ipv4_checksum });
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
		if (payload.len < ipv6.header.offset + ipv6_header_len) {
			errors.push("IPv6 header extends beyond packet length");
		}
		else {
			usz payload_len = payload.len - ipv6.header.offset - ipv6_header_len;
			if (payload_len > 0xffff) {
				errors.push(string::tformat("IPv6 payload length %d exceeds 16 bits", payload_len));
			}
			result.plan.ipv6.set({ .offset = ipv6.header.offset, .header_len = ipv6_header_len });
		}
	}

	HeaderRef? udp = find_header_ref(packet, registry, "UDP");
	if (try udp) {
		if (payload.len < udp.header.offset + 8) {
			errors.push("UDP header extends beyond packet length");
		}
		else {
			usz udp_len = payload.len - udp.header.offset;
			if (udp_len > 0xffff) {
				errors.push(string::tformat("UDP length %d exceeds 16 bits", udp_len));
			}

			result.plan.udp.set({ .offset = udp.header.offset, .checksum = options.udp_checksum });
			if (options.udp_checksum != FixupMode.DISABLED) {
				bool has_pseudo_header = false;
				if (result.plan.ipv4.has_value) {
					result.plan.offload.l2_len = result.plan.ipv4.value.offset;
					result.plan.offload.l3_len = result.plan.ipv4.value.header_len;
					result.plan.offload.l4_len = 8;
					result.plan.offload.layer3 = OffloadLayer3.IPV4;
					has_pseudo_header = true;
				}
				else if (result.plan.ipv6.has_value) {
					result.plan.offload.l2_len = result.plan.ipv6.value.offset;
					result.plan.offload.l3_len = result.plan.ipv6.value.header_len;
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
		if (payload.len < tcp.header.offset + 20) {
			errors.push("TCP header extends beyond packet length");
		}
		else {
			usz tcp_len = payload.len - tcp.header.offset;
			usz tcp_header_len = (usz)(read_u8(payload, tcp.header.offset + 12) >> 4) * 4;
			if (tcp_header_len < 20 || tcp_header_len > tcp_len) {
				errors.push(string::tformat("invalid TCP header length %d bytes", tcp_header_len));
			}

			result.plan.tcp.set({ .offset = tcp.header.offset, .header_len = tcp_header_len, .checksum = options.tcp_checksum });
			if (options.tcp_checksum != FixupMode.DISABLED) {
				bool has_pseudo_header = false;
				if (result.plan.ipv4.has_value) {
					result.plan.offload.l2_len = result.plan.ipv4.value.offset;
					result.plan.offload.l3_len = result.plan.ipv4.value.header_len;
					result.plan.offload.l4_len = tcp_header_len;
					result.plan.offload.layer3 = OffloadLayer3.IPV4;
					has_pseudo_header = true;
				}
				else if (result.plan.ipv6.has_value) {
					result.plan.offload.l2_len = result.plan.ipv6.value.offset;
					result.plan.offload.l3_len = result.plan.ipv6.value.header_len;
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
			if (payload.len < icmp.header.offset + 4) {
				errors.push("ICMP header extends beyond packet length");
			}
			else if (options.icmp_checksum == FixupMode.HARDWARE_OFFLOAD) {
				errors.push("ICMP hardware checksum offload is not supported");
			}
			else {
				result.plan.icmp.set({ .offset = icmp.header.offset, .checksum = options.icmp_checksum });
			}
		}
	}

	populate_ipv4_pseudo_bases(payload, &result.plan);
	result.errors = errors.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

fn void push_fixup_error(List{String}* errors, bool* has_errors, String message) @private {
	if (!*has_errors) {
		errors.init(tmem, 1);
		*has_errors = true;
	}
	errors.push(message);
}

faultdef PSEUDO_HEADER_MISSING;

fn uint? l4_pseudo_sum(char[] payload, PacketFixupPlan plan, char protocol, uint l4_len) @private {
	if (plan.ipv4.has_value) {
		return ipv4_pseudo_sum(payload, plan.ipv4.value.offset, protocol, (ushort)l4_len);
	}
	if (plan.ipv6.has_value) {
		return ipv6_pseudo_sum(payload, plan.ipv6.value.offset, protocol, l4_len);
	}
	return PSEUDO_HEADER_MISSING~;
}

fn uint? l4_pseudo_sum_with_delta(char[] payload, PacketFixupPlan plan, char protocol, uint l4_len, uint ipv4_pseudo_delta) @private {
	uint base;
	if (protocol == UDP_PROTOCOL && plan.udp_ipv4_pseudo_base.has_value) {
		base = plan.udp_ipv4_pseudo_base.value;
	} else if (protocol == TCP_PROTOCOL && plan.tcp_ipv4_pseudo_base.has_value) {
		base = plan.tcp_ipv4_pseudo_base.value;
	} else {
		uint? computed = l4_pseudo_sum(payload, plan, protocol, l4_len);
		if (catch computed) return PSEUDO_HEADER_MISSING~;
		base = computed;
	}
	return base + ipv4_pseudo_delta;
}

fn void populate_ipv4_pseudo_bases(char[] payload, PacketFixupPlan* plan) @private {
	if (!plan.ipv4.has_value) return;
	usz ip_offset = plan.ipv4.value.offset;
	if (plan.udp.has_value && plan.udp.value.checksum != FixupMode.DISABLED) {
		usz udp_len = payload.len - plan.udp.value.offset;
		plan.udp_ipv4_pseudo_base.set(ipv4_pseudo_sum(payload, ip_offset, UDP_PROTOCOL, (ushort)udp_len));
	}
	if (plan.tcp.has_value && plan.tcp.value.checksum != FixupMode.DISABLED) {
		usz tcp_len = payload.len - plan.tcp.value.offset;
		plan.tcp_ipv4_pseudo_base.set(ipv4_pseudo_sum(payload, ip_offset, TCP_PROTOCOL, (ushort)tcp_len));
	}
}

fn FixupResult apply_fixup_plan(char[] payload, PacketFixupPlan plan) {
	FixupResult result;
	result.offload = plan.offload;
	List{String} errors;
	bool has_errors = false;

	if (plan.outer_ipv4.has_value) {
		Ipv4Fixup ipv4 = plan.outer_ipv4.value;
		write_u16(payload, ipv4.offset + 2, (ushort)(payload.len - ipv4.offset));
		if (ipv4.checksum != FixupMode.DISABLED) {
			write_u16(payload, ipv4.offset + 10, 0);
			if (ipv4.checksum == FixupMode.SOFTWARE) {
				write_u16(payload, ipv4.offset + 10, internet_checksum(checksum_sum(payload[ipv4.offset : ipv4.header_len])));
			}
		}
	}
	if (plan.outer_ipv6.has_value) {
		Ipv6Fixup ipv6 = plan.outer_ipv6.value;
		usz payload_len = payload.len - ipv6.offset - ipv6.header_len;
		write_u16(payload, ipv6.offset + 4, (ushort)payload_len);
	}
	if (plan.outer_udp.has_value) {
		UdpFixup udp = plan.outer_udp.value;
		usz udp_len = payload.len - udp.offset;
		write_u16(payload, udp.offset + 4, (ushort)udp_len);
		write_u16(payload, udp.offset + 6, 0);
	}

	if (plan.ipv4.has_value) {
		Ipv4Fixup ipv4 = plan.ipv4.value;
		write_u16(payload, ipv4.offset + 2, (ushort)(payload.len - ipv4.offset));
		if (ipv4.checksum != FixupMode.DISABLED) {
			write_u16(payload, ipv4.offset + 10, 0);
			if (ipv4.checksum == FixupMode.SOFTWARE) {
				write_u16(payload, ipv4.offset + 10, internet_checksum(checksum_sum(payload[ipv4.offset : ipv4.header_len])));
			}
		}
	}
	if (plan.ipv6.has_value) {
		Ipv6Fixup ipv6 = plan.ipv6.value;
		usz payload_len = payload.len - ipv6.offset - ipv6.header_len;
		write_u16(payload, ipv6.offset + 4, (ushort)payload_len);
	}

	if (plan.udp.has_value) {
		UdpFixup udp = plan.udp.value;
		usz udp_len = payload.len - udp.offset;
		write_u16(payload, udp.offset + 4, (ushort)udp_len);
		if (udp.checksum != FixupMode.DISABLED) {
			write_u16(payload, udp.offset + 6, 0);

			uint? pseudo = l4_pseudo_sum(payload, plan, UDP_PROTOCOL, (uint)udp_len);
			if (catch pseudo) {
				push_fixup_error(&errors, &has_errors, "UDP checksum requires IPv4 or IPv6 header");
			}
			else if (udp.checksum == FixupMode.SOFTWARE) {
				ushort checksum = internet_checksum(pseudo + checksum_sum(payload[udp.offset : udp_len]));
				if (checksum == 0) checksum = 0xffff;
				write_u16(payload, udp.offset + 6, checksum);
			}
			else if (udp.checksum == FixupMode.HARDWARE_OFFLOAD) {
				write_u16(payload, udp.offset + 6, fold_checksum(pseudo));
			}
		}
	}
	if (plan.tcp.has_value && plan.tcp.value.checksum != FixupMode.DISABLED) {
		TcpFixup tcp = plan.tcp.value;
		write_u16(payload, tcp.offset + 16, 0);
		usz tcp_len = payload.len - tcp.offset;

		uint? pseudo = l4_pseudo_sum(payload, plan, TCP_PROTOCOL, (uint)tcp_len);
		if (catch pseudo) {
			push_fixup_error(&errors, &has_errors, "TCP checksum requires IPv4 or IPv6 header");
		}
		else if (tcp.checksum == FixupMode.SOFTWARE) {
			write_u16(payload, tcp.offset + 16, internet_checksum(pseudo + checksum_sum(payload[tcp.offset : tcp_len])));
		}
		else if (tcp.checksum == FixupMode.HARDWARE_OFFLOAD) {
			write_u16(payload, tcp.offset + 16, fold_checksum(pseudo));
		}
	}
	if (plan.icmp.has_value && plan.icmp.value.checksum != FixupMode.DISABLED) {
		IcmpFixup icmp = plan.icmp.value;
		write_u16(payload, icmp.offset + 2, 0);
		write_u16(payload, icmp.offset + 2,
			internet_checksum(checksum_sum(payload[icmp.offset : payload.len - icmp.offset])));
	}

	if (has_errors) {
		result.errors = errors.to_tarray();
		return result;
	}

	result.ok = true;
	return result;
}

<* Refreshes checksum fields only. Use this when the payload was copied from a
   fully fixed-up base packet and only flow-varying fields were patched. This
   deliberately does not rewrite IPv4/IPv6/UDP length fields. *>
fn FixupResult apply_checksum_fixup_plan(char[] payload, PacketFixupPlan plan, uint ipv4_pseudo_delta = 0) {
	FixupResult result;
	result.offload = plan.offload;
	List{String} errors;
	bool has_errors = false;

	if (plan.outer_ipv4.has_value) {
		Ipv4Fixup ipv4 = plan.outer_ipv4.value;
		if (ipv4.checksum != FixupMode.DISABLED) {
			write_u16(payload, ipv4.offset + 10, 0);
			if (ipv4.checksum == FixupMode.SOFTWARE) {
				write_u16(payload, ipv4.offset + 10, internet_checksum(checksum_sum(payload[ipv4.offset : ipv4.header_len])));
			}
		}
	}
	if (plan.outer_udp.has_value) {
		write_u16(payload, plan.outer_udp.value.offset + 6, 0);
	}

	if (plan.ipv4.has_value) {
		Ipv4Fixup ipv4 = plan.ipv4.value;
		if (ipv4.checksum != FixupMode.DISABLED) {
			write_u16(payload, ipv4.offset + 10, 0);
			if (ipv4.checksum == FixupMode.SOFTWARE) {
				write_u16(payload, ipv4.offset + 10, internet_checksum(checksum_sum(payload[ipv4.offset : ipv4.header_len])));
			}
		}
	}

	if (plan.udp.has_value) {
		UdpFixup udp = plan.udp.value;
		usz udp_len = payload.len - udp.offset;
		if (udp.checksum != FixupMode.DISABLED) {
			write_u16(payload, udp.offset + 6, 0);

			uint? pseudo = l4_pseudo_sum_with_delta(payload, plan, UDP_PROTOCOL, (uint)udp_len, ipv4_pseudo_delta);
			if (catch pseudo) {
				push_fixup_error(&errors, &has_errors, "UDP checksum requires IPv4 or IPv6 header");
			}
			else if (udp.checksum == FixupMode.SOFTWARE) {
				ushort checksum = internet_checksum(pseudo + checksum_sum(payload[udp.offset : udp_len]));
				if (checksum == 0) checksum = 0xffff;
				write_u16(payload, udp.offset + 6, checksum);
			}
			else if (udp.checksum == FixupMode.HARDWARE_OFFLOAD) {
				write_u16(payload, udp.offset + 6, fold_checksum(pseudo));
			}
		}
	}
	if (plan.tcp.has_value && plan.tcp.value.checksum != FixupMode.DISABLED) {
		TcpFixup tcp = plan.tcp.value;
		write_u16(payload, tcp.offset + 16, 0);
		usz tcp_len = payload.len - tcp.offset;

		uint? pseudo = l4_pseudo_sum_with_delta(payload, plan, TCP_PROTOCOL, (uint)tcp_len, ipv4_pseudo_delta);
		if (catch pseudo) {
			push_fixup_error(&errors, &has_errors, "TCP checksum requires IPv4 or IPv6 header");
		}
		else if (tcp.checksum == FixupMode.SOFTWARE) {
			write_u16(payload, tcp.offset + 16, internet_checksum(pseudo + checksum_sum(payload[tcp.offset : tcp_len])));
		}
		else if (tcp.checksum == FixupMode.HARDWARE_OFFLOAD) {
			write_u16(payload, tcp.offset + 16, fold_checksum(pseudo));
		}
	}
	if (plan.icmp.has_value && plan.icmp.value.checksum != FixupMode.DISABLED) {
		IcmpFixup icmp = plan.icmp.value;
		write_u16(payload, icmp.offset + 2, 0);
		write_u16(payload, icmp.offset + 2,
			internet_checksum(checksum_sum(payload[icmp.offset : payload.len - icmp.offset])));
	}

	if (has_errors) {
		result.errors = errors.to_tarray();
		return result;
	}

	result.ok = true;
	return result;
}

<* @param [&in] registry : `read-only protocol definitions` *>
fn FixupResult fixup_packet(PacketConstructor packet, Registry* registry, char[] payload, FixupOptions options = {}) {
	FixupPlanResult plan = plan_packet_fixups(packet, registry, payload, options);
	if (!plan.ok) {
		return { .ok = false, .errors = plan.errors, .offload = plan.plan.offload };
	}
	return apply_fixup_plan(payload, plan.plan);
}
