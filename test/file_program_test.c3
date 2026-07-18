module flowforge_file_program_test;
import flowforge::ast;
import flowforge::file_program;
import flowforge::generator;
import flowforge::testutil;

fn void test_file_program_accepts_packet_and_count() @test {
	Program program = testutil::must_parse_program(
		"PACKET: IP()\nPACKET_COUNT: 3\n");
	FileProgram result = file_program::parse(program);
	assert(result.ok);
	assert(result.has_packet);
	assert(result.packet_count.has_value);
	assert(result.packet_count.value == 3);
	assert(result.errors.len == 0);
}

fn void test_file_program_rejects_non_positive_count() @test {
	Program program = testutil::must_parse_program(
		"PACKET: IP()\nPACKET_COUNT: 0\n");
	FileProgram result = file_program::parse(program);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "variable 'PACKET_COUNT' must be positive");
}

fn void test_file_program_rejects_negative_count() @test {
	Program program = testutil::must_parse_program(
		"PACKET: IP()\nPACKET_COUNT: -1\n");
	FileProgram result = file_program::parse(program);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "variable 'PACKET_COUNT' must be positive");
}

fn void test_file_program_rejects_duplicate_variables() @test {
	Program program = testutil::must_parse_program(
		"PACKET: IP()\nPACKET: Ether()\nPACKET_COUNT: 2\n");
	FileProgram result = file_program::parse(program);
	assert(!result.ok);
	assert(result.errors.len >= 1);
	assert(result.errors[0] == "duplicate variable 'PACKET'");
}

fn void test_file_program_rejects_count_with_cli_override() @test {
	Program program = testutil::must_parse_program(
		"PACKET: IP()\nPACKET_COUNT: 4\n");
	generator::MaybeCount cli;
	cli.set(2);
	FileProgram result = file_program::parse(program, cli);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "PACKET_COUNT and -c cannot both be specified");
}

fn void test_file_program_uses_cli_count_when_absent() @test {
	Program program = testutil::must_parse_program("PACKET: IP()\n");
	generator::MaybeCount cli;
	cli.set(7);
	FileProgram result = file_program::parse(program, cli);
	assert(result.ok);
	assert(result.packet_count.has_value);
	assert(result.packet_count.value == 7);
}

fn void test_file_program_requires_packet() @test {
	Program program = testutil::must_parse_program("PACKET_COUNT: 1\n");
	FileProgram result = file_program::parse(program);
	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0] == "missing mandatory variable 'PACKET'");
}

fn void test_file_program_warns_on_unknown_variables() @test {
	Program program = testutil::must_parse_program(
		"PACKET: IP()\nFOO: 1\n");
	FileProgram result = file_program::parse(program);
	assert(result.ok);
	assert(result.warnings.len == 1);
	assert(result.warnings[0] == "unknown file-mode variable 'FOO'");
}
