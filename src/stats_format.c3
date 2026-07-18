module flowforge::stats_format;

struct ScaledValue {
	double value;
	String prefix;
}

fn ScaledValue scale_decimal(double value) {
	String[4] prefixes = { "", "K", "M", "G" };
	usz index = 0;
	double v = value;
	if (v < 0) v = -v;
	while (v >= 1000.0 && index + 1 < prefixes.len) {
		v /= 1000.0;
		index++;
	}
	double signed_value = value < 0 ? -v : v;
	return { .value = signed_value, .prefix = prefixes[index] };
}

fn String format_human_count(double value) {
	ScaledValue scaled = scale_decimal(value);
	if (!scaled.prefix.len) {
		return string::tformat("%.0f", scaled.value);
	}
	return string::tformat("%.2f %s", scaled.value, scaled.prefix);
}

fn String format_human_rate(double value, String suffix) {
	ScaledValue scaled = scale_decimal(value);
	if (!scaled.prefix.len) {
		return string::tformat("%.0f %s", scaled.value, suffix);
	}
	return string::tformat("%.2f %s%s", scaled.value, scaled.prefix, suffix);
}

fn String format_elapsed_seconds(ulong seconds) {
	ulong hours = seconds / 3600;
	seconds %= 3600;
	ulong minutes = seconds / 60;
	seconds %= 60;
	return string::tformat("%02d:%02d:%02d", hours, minutes, seconds);
}
