module flowforge::header_file;
import flowforge::registry;
import flowforge::cvalue;
import flowforge::value;
import std::collections::list;

<* Result of loading user-defined headers from a definition file.
   The loader augments an existing Registry: it never replaces predefined
   headers or inference rules, and redefining an existing header is an error. *>
struct HeaderFileResult {
	bool ok;
	usz headers_loaded;
	String[] warnings;
	String[] errors;
}

struct Token {
	String text;
	usz line;
	bool punct;
}

struct Loader {
	Token[] tokens;
	usz pos;
	Registry* reg;
	List{String}* errors;
	List{String}* warnings;
	usz loaded;
}

<* Parses a fields-only header definition file and registers each header on
   `reg`. The grammar is deliberately small:

     header <Name> {
         <field> <type>            # e.g. `ttl b8`
         <field> <type> = <int>    # integer default for bit fields
     }

   Lines beginning with `#` (or the trailing part of any line after `#`) are
   comments. Field types are any type understood by the registry (`bN`,
   `bN_ranges`, `mac`, `ipv4`/`ipv6` and their range variants). Integer
   defaults are only accepted on bit-typed fields. *>
fn HeaderFileResult load(Registry* reg, String content) {
	HeaderFileResult result;
	List{String} errors;
	errors.tinit();
	List{String} warnings;
	warnings.tinit();

	Loader loader = {
		.tokens = tokenize(content),
		.reg = reg,
		.errors = &errors,
		.warnings = &warnings,
	};
	loader.run();

	if (loader.loaded == 0 && errors.len() == 0) {
		warnings.push("header file defined no headers");
	}

	result.headers_loaded = loader.loaded;
	result.errors = errors.to_tarray();
	result.warnings = warnings.to_tarray();
	result.ok = errors.len() == 0;
	return result;
}

fn Token[] tokenize(String content) {
	List{Token} tokens;
	tokens.tinit();
	usz line = 1;
	usz i = 0;
	usz n = content.len;
	while (i < n) {
		char c = content[i];
		if (c == '\n') {
			line++;
			i++;
			continue;
		}
		if (c == ' ' || c == '\t' || c == '\r') {
			i++;
			continue;
		}
		if (c == '#') {
			while (i < n && content[i] != '\n') i++;
			continue;
		}
		if (c == '{' || c == '}' || c == '=') {
			tokens.push({ .text = content[i:1], .line = line, .punct = true });
			i++;
			continue;
		}
		usz start = i;
		while (i < n) {
			char d = content[i];
			if (d == ' ' || d == '\t' || d == '\r' || d == '\n' ||
				d == '{' || d == '}' || d == '=' || d == '#') break;
			i++;
		}
		tokens.push({ .text = content[start:i - start], .line = line, .punct = false });
	}
	return tokens.to_tarray();
}

fn bool Loader.at_end(&self) => self.pos >= self.tokens.len;

fn void Loader.run(&self) {
	while (!self.at_end()) {
		Token kw = self.tokens[self.pos];
		if (kw.punct || kw.text != "header") {
			self.errors.push(string::tformat("line %d: expected 'header' keyword but got '%s'", kw.line, kw.text));
			return;
		}
		self.pos++;
		// A structural error (missing name/brace) is unrecoverable because the
		// token stream can no longer be aligned; stop and report what we have.
		if (!self.parse_header()) return;
	}
}

fn bool Loader.parse_header(&self) {
	if (self.at_end()) {
		self.errors.push("expected header name after 'header'");
		return false;
	}
	Token name_tok = self.tokens[self.pos];
	if (name_tok.punct) {
		self.errors.push(string::tformat("line %d: expected header name but got '%s'", name_tok.line, name_tok.text));
		return false;
	}
	String name = name_tok.text;
	self.pos++;

	if (self.at_end() || !(self.tokens[self.pos].punct && self.tokens[self.pos].text == "{")) {
		self.errors.push(string::tformat("line %d: expected '{' after header '%s'", name_tok.line, name));
		return false;
	}
	self.pos++;

	List{FieldInput} fields;
	fields.tinit();
	List{String} field_names;
	field_names.tinit();
	bool header_ok = true;
	usz total_bits = 0;

	while (true) {
		if (self.at_end()) {
			self.errors.push(string::tformat("line %d: unterminated header '%s' (missing '}')", name_tok.line, name));
			return false;
		}
		Token t = self.tokens[self.pos];
		if (t.punct && t.text == "}") {
			self.pos++;
			break;
		}
		if (t.punct) {
			self.errors.push(string::tformat("line %d: expected field name but got '%s'", t.line, t.text));
			return false;
		}
		String fname = t.text;
		self.pos++;

		if (self.at_end() || self.tokens[self.pos].punct) {
			self.errors.push(string::tformat("line %d: expected a type for field '%s'", t.line, fname));
			return false;
		}
		Token type_tok = self.tokens[self.pos];
		String ftype = type_tok.text;
		self.pos++;

		FieldInput fi;
		fi.name = fname.copy(self.reg.allocator);
		fi.type_name = ftype.copy(self.reg.allocator);

		if (!self.at_end() && self.tokens[self.pos].punct && self.tokens[self.pos].text == "=") {
			self.pos++;
			if (self.at_end() || self.tokens[self.pos].punct) {
				self.errors.push(string::tformat("line %d: expected an integer default for field '%s'", type_tok.line, fname));
				return false;
			}
			Token val_tok = self.tokens[self.pos];
			self.pos++;
			ulong? val = val_tok.text.to_ulong();
			if (catch val) {
				self.errors.push(string::tformat("line %d: invalid integer default '%s' for field '%s'", val_tok.line, val_tok.text, fname));
				header_ok = false;
			}
			else if (!(ftype.len && ftype[0] == 'b')) {
				self.errors.push(string::tformat("line %d: default value for field '%s' is only supported on bit ('bN') fields", val_tok.line, fname));
				header_ok = false;
			}
			else {
				fi.default_value.set(value::cv_uint(val));
			}
		}

		usz width = cvalue::bit_width_for_type_name(ftype);
		if (width == 0) {
			self.errors.push(string::tformat("line %d: unknown type '%s' for field '%s'", type_tok.line, ftype, fname));
			header_ok = false;
		}
		total_bits += width;
		if (self.field_name_seen(field_names, fname)) {
			self.errors.push(string::tformat("line %d: duplicate field '%s' in header '%s'", t.line, fname, name));
			header_ok = false;
		}
		else {
			field_names.push(fname);
		}

		ConstructorValue? def = fi.default_value.get();
		if (try def) {
			String verr = "";
			if (!registry::validate_constructor_value(ftype, def, &verr)) {
				self.errors.push(string::tformat("line %d: invalid default for field '%s': %s", type_tok.line, fname, verr));
				header_ok = false;
			}
		}

		fields.push(fi);
	}

	if (fields.len() == 0) {
		self.errors.push(string::tformat("header '%s' has no fields", name));
		header_ok = false;
	}
	// A header must be byte-aligned: the serializer writes whole bytes, so any
	// trailing bits that don't complete a byte would corrupt the packet layout.
	// Only meaningful once every field type is valid (invalid types count 0).
	else if (header_ok && total_bits % 8 != 0) {
		self.errors.push(string::tformat("header '%s' is %d bits wide, which is not a multiple of 8", name, total_bits));
		header_ok = false;
	}
	if (self.reg.has_header(name)) {
		self.errors.push(string::tformat("header '%s' is already defined and cannot be redefined", name));
		header_ok = false;
	}

	if (header_ok) {
		self.reg.register_header(name.copy(self.reg.allocator), fields.to_tarray());
		self.loaded++;
	}
	return true;
}

fn bool Loader.field_name_seen(&self, List{String} names, String name) {
	foreach (n : names) {
		if (n == name) return true;
	}
	return false;
}
