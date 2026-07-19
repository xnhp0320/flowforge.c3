module flowforge_header_file_test @test;
import flowforge::header_file;
import flowforge::registry;
import flowforge::constructor;
import flowforge::serializer;
import flowforge::value;
import flowforge::testutil;

fn void test_loads_fields_only_header() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, `
		header MyHdr {
			kind b8
			flags b8
			value b16
		}
	`);

	assert(result.ok);
	assert(result.errors.len == 0);
	assert(result.headers_loaded == 1);

	HeaderSpec* spec = reg.find_header("MyHdr")!!;
	assert(spec.bit_width == 32);
	assert(spec.fields.len == 3);
	assert(spec.fields[0].name == "kind");
	assert(spec.fields[0].bit_offset == 0);
	assert(spec.fields[0].bit_width == 8);
	assert(spec.fields[2].name == "value");
	assert(spec.fields[2].bit_offset == 16);
	assert(spec.fields[2].bit_width == 16);
}

fn void test_augments_default_registry_without_replacing() @test {
	Registry reg = registry::create_default_registry();
	HeaderFileResult result = header_file::load(&reg, "header Custom { a b16 }");

	assert(result.ok);
	assert(result.headers_loaded == 1);
	// Predefined headers are still present alongside the new one.
	assert(reg.has_header("Ether"));
	assert(reg.has_header("IP"));
	assert(reg.has_header("Custom"));
}

fn void test_redefining_predefined_header_is_rejected() @test {
	Registry reg = registry::create_default_registry();
	HeaderFileResult result = header_file::load(&reg, "header Ether { x b8 }");

	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("Ether"));
	assert(result.errors[0].contains("already defined"));
}

fn void test_bit_field_default_is_applied() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { version b4 = 6 ihl b4 = 5 ttl b8 = 0x40 }");

	assert(result.ok);
	HeaderSpec* spec = reg.find_header("H")!!;
	assert(value::cv_equals(spec.fields[0].default_value, value::cv_uint(6)));
	assert(value::cv_equals(spec.fields[1].default_value, value::cv_uint(5)));
	assert(value::cv_equals(spec.fields[2].default_value, value::cv_uint(64)));
}

fn void test_default_on_non_bit_field_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { addr mac = 5 }");

	assert(!result.ok);
	assert(result.errors[0].contains("only supported on bit"));
}

fn void test_default_out_of_range_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { small b4 = 99 }");

	assert(!result.ok);
	assert(result.errors[0].contains("does not fit"));
}

fn void test_unknown_type_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { field b0 other nonsense }");

	assert(!result.ok);
	assert(result.errors.len == 2);
	assert(result.errors[0].contains("b0"));
	assert(result.errors[1].contains("nonsense"));
	assert(!reg.has_header("H"));
}

fn void test_duplicate_field_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { a b8 a b16 }");

	assert(!result.ok);
	assert(result.errors[0].contains("duplicate field 'a'"));
}

fn void test_empty_header_body_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { }");

	assert(!result.ok);
	assert(result.errors[0].contains("no fields"));
}

fn void test_missing_closing_brace_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { a b8");

	assert(!result.ok);
	assert(result.errors[0].contains("unterminated"));
}

fn void test_comments_and_whitespace_are_ignored() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, `
		# a user-defined header
		header H {
			kind b8   # message kind
			len  b16  # payload length
		}
	`);

	assert(result.ok);
	assert(result.headers_loaded == 1);
	HeaderSpec* spec = reg.find_header("H")!!;
	assert(spec.fields.len == 2);
}

fn void test_multiple_headers_load() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg,
		"header A { x b8 } header B { y b16 z mac }");

	assert(result.ok);
	assert(result.headers_loaded == 2);
	assert(reg.has_header("A"));
	assert(reg.has_header("B"));
}

fn void test_loaded_header_serializes_end_to_end() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult loaded = header_file::load(&reg,
		"header MyHdr { kind b8 flags b8 value b16 }");
	assert(loaded.ok);

	BuildResult built = constructor::build(&reg, testutil::must_parse("MyHdr(kind=1,flags=2,value=0x0304)"));
	assert(built.ok);

	char[16] buf;
	SerializeResult result = serializer::serialize_packet(built.packet, &reg, buf[..]);
	assert(result.ok);
	assert(result.packet_len == 4);
	assert(buf[0] == 1);
	assert(buf[1] == 2);
	assert(buf[2] == 0x03);
	assert(buf[3] == 0x04);
}

fn void test_non_byte_aligned_header_is_rejected() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { a b4 b b3 }");

	assert(!result.ok);
	assert(result.errors.len == 1);
	assert(result.errors[0].contains("not a multiple of 8"));
	assert(!reg.has_header("H"));
}

fn void test_byte_aligned_multi_field_header_is_accepted() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "header H { a b4 b b4 c b8 }");

	assert(result.ok);
	assert(result.headers_loaded == 1);
	HeaderSpec* spec = reg.find_header("H")!!;
	assert(spec.bit_width == 16);
}

fn void test_empty_file_warns_but_succeeds() @test {
	Registry reg = registry::create_empty_registry();
	HeaderFileResult result = header_file::load(&reg, "   # just a comment\n");

	assert(result.ok);
	assert(result.headers_loaded == 0);
	assert(result.warnings.len == 1);
	assert(result.warnings[0].contains("no headers"));
}
