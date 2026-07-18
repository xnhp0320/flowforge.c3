module flowforge_stats_format_test;
import flowforge::stats_format;

fn void test_formats_counts() @test {
	assert(stats_format::format_human_count(999) == "999");
	assert(stats_format::format_human_count(1500) == "1.50 K");
	assert(stats_format::format_human_count(2000000) == "2.00 M");
}

fn void test_formats_rates() @test {
	assert(stats_format::format_human_rate(999, "pps") == "999 pps");
	assert(stats_format::format_human_rate(1500, "pps") == "1.50 Kpps");
	assert(stats_format::format_human_rate(2000000, "pps") == "2.00 Mpps");
	assert(stats_format::format_human_rate(800, "bps") == "800 bps");
	assert(stats_format::format_human_rate(1200000, "bps") == "1.20 Mbps");
	assert(stats_format::format_human_rate(3400000000.0, "bps") == "3.40 Gbps");
}

fn void test_formats_elapsed_seconds() @test {
	assert(stats_format::format_elapsed_seconds(1) == "00:00:01");
	assert(stats_format::format_elapsed_seconds(3723) == "01:02:03");
}
