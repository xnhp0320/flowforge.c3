module flowforge::generator;
import flowforge::ast;
import flowforge::checker;
import flowforge::constructor;
import flowforge::registry;
import flowforge::serializer;
import std::collections::list;
import std::collections::maybe;

alias MaybeCount = Maybe{ulong};

const usz GENERATOR_MAX_PACKET_SIZE = 2048;
const ulong ULONG_MAX = 0xFFFFFFFFFFFFFFFF;

struct FlowIndexPlan {
	ulong total_flows;
	ulong planned_packets;
}

struct GeneratedPacket {
	PacketConstructor constructor;
	char[] base_payload;
	PayloadFieldModifier[] modifiers;
	PacketFixupPlan fixup_plan;
	usz packet_len;
	FlowIndexPlan flow_plan;
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

<* Runs check → construct → serialize → fixup and plans range expansion. *>
fn PacketGenerationResult PacketGenerator.prepare(&self, Packet packet, MaybeCount packet_count = {}, FixupOptions fixup_options = {}) {
	PacketGenerationResult result;
	List{String} warnings;
	warnings.tinit();
	List{String} errors;
	errors.tinit();

	Checker checker = { .registry = *self.registry };
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
	if (!self.serialize_generated(built.packet, fixup_options, &generated, &errors)) {
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

<* Fills `payload` with the base packet then patches in the given flow. *>
fn bool PacketGenerator.payload_for_flow(&self, GeneratedPacket* packet, ulong flow_index, List{char}* payload, List{String}* errors) {
	if (packet.base_payload.len != packet.packet_len) {
		errors.push("base payload length does not match packet length");
		return false;
	}
	payload.clear();
	foreach (b : packet.base_payload) payload.push(b);
	return self.apply_flow(packet, flow_index, payload.array_view(), errors);
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

fn bool PacketGenerator.serialize_generated(&self, PacketConstructor packet, FixupOptions fixup_options, GeneratedPacket* out, List{String}* errors) {
	List{char} scratch;
	scratch.tinit();
	for (usz i = 0; i < GENERATOR_MAX_PACKET_SIZE; i++) scratch.push(0);
	char[] payload = scratch.array_view();

	SerializeResult serialized = serializer::serialize_packet(packet, self.registry, payload);
	foreach (e : serialized.errors) errors.push(e);
	if (!serialized.ok) return false;

	FixupPlanResult plan = serializer::plan_packet_fixups(packet, self.registry, payload, serialized.packet_len, fixup_options);
	foreach (e : plan.errors) errors.push(e);
	if (!plan.ok) return false;

	FixupResult fixed = serializer::apply_fixup_plan(payload, plan.plan);
	foreach (e : fixed.errors) errors.push(e);
	if (!fixed.ok) return false;

	*out = {
		.constructor = packet,
		.base_payload = payload[:serialized.packet_len],
		.modifiers = serialized.modifiers,
		.fixup_plan = plan.plan,
		.packet_len = serialized.packet_len,
		.flow_plan = {},
	};
	return true;
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
