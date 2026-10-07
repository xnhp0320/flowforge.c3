module flowforge::pcap;
import std::io;

faultdef WRITE_FAILED, HEADER_NOT_WRITTEN, PACKET_TOO_LARGE;

const uint PCAP_MAGIC = 0xa1b2c3d4;
const ushort PCAP_MAJOR = 2;
const ushort PCAP_MINOR = 4;
const uint PCAP_SNAPLEN = 65535;
const uint PCAP_LINKTYPE_ETHERNET = 1;

<* Writes classic (little-endian) pcap bytes to any OutStream
   (an in-memory ByteWriter, a File, etc.), mirroring the C++ ostream sink. *>
struct PcapWriter {
	OutStream output;
	bool wrote_header;
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

fn void? PcapWriter.write_header(&self) {
	self.write_header_bytes()!;
	self.wrote_header = true;
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

fn void? PcapWriter.write_packet(&self, char[] payload) {
	if (!self.wrote_header) return HEADER_NOT_WRITTEN~;
	if (payload.len > PCAP_SNAPLEN) return PACKET_TOO_LARGE~;
	self.write_packet_bytes(payload)!;
}

fn void? PcapWriter.write_packet_bytes(&self, char[] payload) {
	uint len = (uint)payload.len;
	write_u32_le(self.output, 0)!;
	write_u32_le(self.output, 0)!;
	write_u32_le(self.output, len)!;
	write_u32_le(self.output, len)!;
	sz written = self.output.write(payload)!;
	// OutStream.write faults on failure; only a genuine short write remains.
	if ((usz)written != payload.len) return WRITE_FAILED~;
}
