# Agent guidelines — flowforge.c3

## Brace style (required)

Use **K&R / same-line braces**: the opening `{` stays on the same line as the statement or declaration it belongs to. Do **not** put `{` alone on the next line (Allman / C3 default sample style).

```c3
// Good
fn void Lexer.init(&self, String source) {
	self.source = source;
}

if (catch value) {
	return PARSE_ERROR~;
}

struct Parser {
	Lexer lexer;
	String error;
}

// Bad — do not use
fn void Lexer.init(&self, String source)
{
	self.source = source;
}
```

This applies to functions, methods, structs, `if` / `else` / `while` / `for` / `switch`, and similar blocks.

Multi-line compound literals / array arguments may still start a new line when that is clearer, e.g.:

```c3
self.add_header("Ether",
	{ "dst", "src", "type" },
	{ "mac", "mac", "b16" },
	{});
```
