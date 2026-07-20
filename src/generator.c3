module flowforge::generator;
import flowforge::ast;
import flowforge::checker;
import flowforge::constructor;
import flowforge::registry;
import flowforge::serializer;
import flowforge::value;
import std::collections::list;
import std::collections::maybe;

faultdef GENERATE_ERR;

alias MaybeCount = Maybe{ulong};

const usz GENERATOR_MAX_PACKET_SIZE = 2048;
const ulong ULONG_MAX = 0xFFFFFFFFFFFFFFFF;

struct FlowIndexPlan {
	ulong total_flows;
	ulong planned_packets;
}

struct GeneratedPacket {
	char[] base_payload;
	PayloadFieldModifier[] modifiers;
	PacketFixupPlan fixup_plan;
	usz packet_len;
	FlowIndexPlan flow_plan;
	Allocator allocator;
}

struct PacketGenerationResult {
	bool ok;
	String[] warnings;
	String[] errors;
	bool has_packet;
	GeneratedPacket packet;
}

struct PacketGenerator {
	Registry* registry;
}

<* Runs check → construct → serialize → fixup and plans range expansion.
   The persistent parts of the returned GeneratedPacket (base payload and
   modifiers) are allocated from `alloc`; call GeneratedPacket.free() to
   release them when `alloc` is a heap allocator. *>
fn PacketGenerationResult PacketGenerator.prepare(&self, Packet packet, MaybeCount packet_count = {}, FixupOptions fixup_options = {}, Allocator alloc = tmem) {
	PacketGenerationResult result;
	List{String} warnings;
	warnings.tinit();
	List{String} errors;
	errors.tinit();

	Checker checker = { .registry = self.registry };
	CheckResult check = checker.check(packet);
	foreach (w : check.warnings) warnings.push(w);
	foreach (e : check.errors) errors.push(e);
	if (!check.ok) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}

	BuildResult built = constructor::build(self.registry, packet);
	foreach (w : built.warnings) warnings.push(w);
	foreach (e : built.errors) errors.push(e);
	if (!built.ok) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}

	GeneratedPacket generated;
	if (!self.serialize_generated(built.packet, fixup_options, &generated, &errors, alloc)) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}

	FlowIndexPlan flow_plan;
	if (!plan_flow_indexes(generated.modifiers, packet_count, &flow_plan, &errors)) {
		result.warnings = warnings.to_tarray();
		result.errors = errors.to_tarray();
		return result;
	}
	generated.flow_plan = flow_plan;

	result.ok = true;
	result.has_packet = true;
	result.packet = generated;
	result.warnings = warnings.to_tarray();
	result.errors = errors.to_tarray();
	return result;
}

<* Returns a freshly allocated payload (owned by `alloc`) for the given flow. *>
fn char[]? PacketGenerator.payload_for_flow(&self, GeneratedPacket* packet, ulong flow_index, Allocator alloc, List{String}* errors) {
	if (packet.base_payload.len != packet.packet_len) {
		errors.push("base payload length does not match packet length");
		return GENERATE_ERR~;
	}
	char[] payload = alloc::new_array(alloc, char, (sz)packet.packet_len);
	mem::copy(payload.ptr, packet.base_payload.ptr, (sz)packet.packet_len);
	if (!self.apply_flow(packet, flow_index, payload, errors)) {
		alloc::free(alloc, payload.ptr);
		return GENERATE_ERR~;
	}
	return payload;
}

<* Patches an already-populated buffer to represent a specific flow. *>
fn bool PacketGenerator.apply_flow(&self, GeneratedPacket* packet, ulong flow_index, char[] payload, List{String}* errors) {
	if (flow_index >= packet.flow_plan.planned_packets) {
		errors.push("flow index is outside the planned packet count");
		return false;
	}
	if (payload.len < packet.packet_len) {
		errors.push("payload buffer is smaller than the packet length");
		return false;
	}

	char[] packet_payload = payload[:packet.packet_len];
	if (!apply_flow_index(packet_payload, packet.modifiers, flow_index, errors)) {
		return false;
	}

	FixupResult fixed = serializer::apply_fixup_plan(packet_payload, packet.fixup_plan);
	foreach (e : fixed.errors) errors.push(e);
	return fixed.ok;
}

<* Patches a payload that was copied from `GeneratedPacket.base_payload` and
   refreshes only checksum fields. Length fields are assumed to already be
   fixed in the seeded base payload. *>
fn bool PacketGenerator.apply_flow_checksums_only(&self, GeneratedPacket* packet, ulong flow_index, char[] payload, List{String}* errors) {
	if (flow_index >= packet.flow_plan.planned_packets) {
		errors.push("flow index is outside the planned packet count");
		return false;
	}
	if (payload.len < packet.packet_len) {
		errors.push("payload buffer is smaller than the packet length");
		return false;
	}

	char[] packet_payload = payload[:packet.packet_len];
	if (!apply_flow_index(packet_payload, packet.modifiers, flow_index, errors)) {
		return false;
	}

	FixupResult fixed = serializer::apply_checksum_fixup_plan(packet_payload, packet.fixup_plan);
	foreach (e : fixed.errors) errors.push(e);
	return fixed.ok;
}

fn bool PacketGenerator.serialize_generated(&self, PacketConstructor packet, FixupOptions fixup_options, GeneratedPacket* out, List{String}* errors, Allocator alloc) {
	char[GENERATOR_MAX_PACKET_SIZE] scratch;

	SerializeResult serialized = serializer::serialize_packet(packet, self.registry, scratch[..]);
	foreach (e : serialized.errors) errors.push(e);
	if (!serialized.ok) return false;

	FixupPlanResult plan = serializer::plan_packet_fixups(packet, self.registry, scratch[..], serialized.packet_len, fixup_options);
	foreach (e : plan.errors) errors.push(e);
	if (!plan.ok) return false;

	FixupResult fixed = serializer::apply_fixup_plan(scratch[..], plan.plan);
	foreach (e : fixed.errors) errors.push(e);
	if (!fixed.ok) return false;

	char[] base_payload = alloc::new_array(alloc, char, (sz)serialized.packet_len);
	mem::copy(base_payload.ptr, &scratch[0], (sz)serialized.packet_len);

	*out = {
		.base_payload = base_payload,
		.modifiers = copy_modifiers(serialized.modifiers, alloc),
		.fixup_plan = plan.plan,
		.packet_len = serialized.packet_len,
		.flow_plan = {},
		.allocator = alloc,
	};
	return true;
}

<* Deep-copies the serializer's (temp-allocated) modifiers into `alloc` so the
   GeneratedPacket owns them independently of the temp arena. *>
fn PayloadFieldModifier[] copy_modifiers(PayloadFieldModifier[] src, Allocator alloc) {
	if (src.len == 0) return {};
	PayloadFieldModifier[] dst = alloc::new_array(alloc, PayloadFieldModifier, (sz)src.len);
	for (usz i = 0; i < src.len; i++) {
		PayloadFieldModifier m = src[i];
		m.protocol = m.protocol.copy(alloc);
		m.field = m.field.copy(alloc);
		switch (m.values_kind) {
			case ModifierValueKind.UINT_RANGES:
				m.uint_ranges = dup_uint_ranges(m.uint_ranges, alloc);
			case ModifierValueKind.IPV4_RANGES:
				m.ipv4_ranges = dup_ipv4_ranges(m.ipv4_ranges, alloc);
			case ModifierValueKind.IPV6_RANGES:
				m.ipv6_ranges = dup_ipv6_ranges(m.ipv6_ranges, alloc);
		}
		dst[i] = m;
	}
	return dst;
}

fn UIntRange[] dup_uint_ranges(UIntRange[] src, Allocator alloc) {
	if (src.len == 0) return {};
	UIntRange[] dst = alloc::new_array(alloc, UIntRange, (sz)src.len);
	foreach (i, r : src) dst[i] = r;
	return dst;
}

fn IPv4Range[] dup_ipv4_ranges(IPv4Range[] src, Allocator alloc) {
	if (src.len == 0) return {};
	IPv4Range[] dst = alloc::new_array(alloc, IPv4Range, (sz)src.len);
	foreach (i, r : src) dst[i] = r;
	return dst;
}

fn IPv6Range[] dup_ipv6_ranges(IPv6Range[] src, Allocator alloc) {
	if (src.len == 0) return {};
	IPv6Range[] dst = alloc::new_array(alloc, IPv6Range, (sz)src.len);
	foreach (i, r : src) dst[i] = r;
	return dst;
}

<* Releases the base payload and modifiers. Only call this when prepare() was
   given a heap allocator; for the default temp allocator it is unnecessary. *>
fn void GeneratedPacket.free(&self) {
	if (!self.allocator) return;
	foreach (&m : self.modifiers) {
		switch (m.values_kind) {
			case ModifierValueKind.UINT_RANGES:
				if (m.uint_ranges.len) alloc::free(self.allocator, m.uint_ranges.ptr);
			case ModifierValueKind.IPV4_RANGES:
				if (m.ipv4_ranges.len) alloc::free(self.allocator, m.ipv4_ranges.ptr);
			case ModifierValueKind.IPV6_RANGES:
				if (m.ipv6_ranges.len) alloc::free(self.allocator, m.ipv6_ranges.ptr);
		}
		if (m.protocol.len) alloc::free(self.allocator, m.protocol.ptr);
		if (m.field.len) alloc::free(self.allocator, m.field.ptr);
	}
	if (self.modifiers.len) alloc::free(self.allocator, self.modifiers.ptr);
	if (self.base_payload.len) alloc::free(self.allocator, self.base_payload.ptr);
	*self = {};
}

fn bool plan_flow_indexes(PayloadFieldModifier[] modifiers, MaybeCount packet_count, FlowIndexPlan* out, List{String}* errors) {
	FlowIndexPlan plan = { .total_flows = 1, .planned_packets = 1 };
	foreach (m : modifiers) {
		if (m.value_count == 0) {
			errors.push(string::tformat("modifier '%s.%s' has zero values", m.protocol, m.field));
			return false;
		}
		if (plan.total_flows > ULONG_MAX / m.value_count) {
			errors.push("range expansion has more than 18446744073709551615 flows");
			return false;
		}
		plan.total_flows *= m.value_count;
	}

	ulong? count = packet_count.get();
	if (try count) {
		plan.planned_packets = plan.total_flows < count ? plan.total_flows : count;
	}
	else {
		plan.planned_packets = plan.total_flows;
	}
	*out = plan;
	return true;
}

fn bool apply_flow_index(char[] payload, PayloadFieldModifier[] modifiers, ulong flow_index, List{String}* errors) {
	ulong remaining = flow_index;
	foreach (&m : modifiers) {
		ulong value_index = remaining % m.value_count;
		remaining /= m.value_count;
		String err = "";
		if (!m.apply(payload, value_index, &err)) {
			errors.push(err);
			return false;
		}
	}
	return true;
}
