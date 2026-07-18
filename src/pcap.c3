module flowforge::pcap;
import std::collections::list;

const uint PCAP_MAGIC = 0xa1b2c3d4;
const ushort PCAP_MAJOR = 2;
const ushort PCAP_MINOR = 4;
const uint PCAP_SNAPLEN = 65535;
const uint PCAP_LINKTYPE_ETHERNET = 1;

struct PcapWriteResult {
	bool ok;
	String[] errors;
}

<* Appends classic (little-endian) pcap bytes to a growable buffer. *>
struct PcapWriter {
	List{char}* output;
	bool wrote_header;
}

fn PcapWriteResult single_error(String message) {
	List{String} errors;
	errors.tinit();
	errors.push(message);
	return { .ok = false, .errors = errors.to_tarray() };
}

fn void write_u16_le(List{char}* out, ushort value) {
	out.push((char)(value & 0xff));
	out.push((char)((value >> 8) & 0xff));
}

fn void write_u32_le(List{char}* out, uint value) {
	out.push((char)(value & 0xff));
	out.push((char)((value >> 8) & 0xff));
	out.push((char)((value >> 16) & 0xff));
	out.push((char)((value >> 24) & 0xff));
}

fn PcapWriteResult PcapWriter.write_header(&self) {
	write_u32_le(self.output, PCAP_MAGIC);
	write_u16_le(self.output, PCAP_MAJOR);
	write_u16_le(self.output, PCAP_MINOR);
	write_u32_le(self.output, 0);
	write_u32_le(self.output, 0);
	write_u32_le(self.output, PCAP_SNAPLEN);
	write_u32_le(self.output, PCAP_LINKTYPE_ETHERNET);
	self.wrote_header = true;
	return { .ok = true };
}

fn PcapWriteResult PcapWriter.write_packet(&self, char[] payload) {
	if (!self.wrote_header) {
		return single_error("pcap header must be written before packet records");
	}
	if (payload.len > PCAP_SNAPLEN) {
		return single_error("packet is too large for pcap output");
	}

	uint len = (uint)payload.len;
	write_u32_le(self.output, 0);
	write_u32_le(self.output, 0);
	write_u32_le(self.output, len);
	write_u32_le(self.output, len);
	foreach (b : payload) self.output.push(b);
	return { .ok = true };
}
