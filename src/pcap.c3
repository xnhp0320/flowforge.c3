module flowforge::pcap;
import std::collections::list;
import std::io;

faultdef WRITE_FAILED;

const uint PCAP_MAGIC = 0xa1b2c3d4;
const ushort PCAP_MAJOR = 2;
const ushort PCAP_MINOR = 4;
const uint PCAP_SNAPLEN = 65535;
const uint PCAP_LINKTYPE_ETHERNET = 1;

struct PcapWriteResult {
	bool ok;
	String[] errors;
}

<* Writes classic (little-endian) pcap bytes to any OutStream
   (an in-memory ByteWriter, a File, etc.), mirroring the C++ ostream sink. *>
struct PcapWriter {
	OutStream output;
	bool wrote_header;
}

fn PcapWriteResult single_error(String message) {
	List{String} errors;
	errors.tinit();
	errors.push(message);
	return { .ok = false, .errors = errors.to_tarray() };
}

fn void? write_u16_le(OutStream out, ushort value) {
	out.write_byte((char)(value & 0xff))!;
	out.write_byte((char)((value >> 8) & 0xff))!;
}

fn void? write_u32_le(OutStream out, uint value) {
	out.write_byte((char)(value & 0xff))!;
	out.write_byte((char)((value >> 8) & 0xff))!;
	out.write_byte((char)((value >> 16) & 0xff))!;
	out.write_byte((char)((value >> 24) & 0xff))!;
}

fn PcapWriteResult PcapWriter.write_header(&self) {
	if (catch self.write_header_bytes()) {
		return single_error("failed to write pcap output");
	}
	self.wrote_header = true;
	return { .ok = true };
}

fn void? PcapWriter.write_header_bytes(&self) {
	write_u32_le(self.output, PCAP_MAGIC)!;
	write_u16_le(self.output, PCAP_MAJOR)!;
	write_u16_le(self.output, PCAP_MINOR)!;
	write_u32_le(self.output, 0)!;
	write_u32_le(self.output, 0)!;
	write_u32_le(self.output, PCAP_SNAPLEN)!;
	write_u32_le(self.output, PCAP_LINKTYPE_ETHERNET)!;
}

fn PcapWriteResult PcapWriter.write_packet(&self, char[] payload) {
	if (!self.wrote_header) {
		return single_error("pcap header must be written before packet records");
	}
	if (payload.len > PCAP_SNAPLEN) {
		return single_error("packet is too large for pcap output");
	}
	if (catch self.write_packet_bytes(payload)) {
		return single_error("failed to write pcap output");
	}
	return { .ok = true };
}

fn void? PcapWriter.write_packet_bytes(&self, char[] payload) {
	uint len = (uint)payload.len;
	write_u32_le(self.output, 0)!;
	write_u32_le(self.output, 0)!;
	write_u32_le(self.output, len)!;
	write_u32_le(self.output, len)!;
	sz written = self.output.write(payload)!;
	if (written < 0 || (usz)written != payload.len) return WRITE_FAILED~;
}
