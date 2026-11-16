"""Focused tests for critical-path pool-lifetime lint."""

import tempfile
import unittest
from pathlib import Path

import lint_critical_path


class CriticalPathLintTests(unittest.TestCase):
    def check_source(self, source: str, helper: str = "") -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            worker = root / "worker.c3"
            worker.write_text(source)
            paths = [worker]
            if helper:
                helper_path = root / "helper.c3"
                helper_path.write_text(helper)
                paths.append(helper_path)
            return lint_critical_path.lint(paths, ("worker:hot",), root)

    def test_repeated_helper_without_pool_fails(self) -> None:
        problems = self.check_source(
            "fn void hot() { while (true) { helper::allocate(); } }",
            "fn void allocate() { List{String} errors; errors.tinit(); }",
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("helper:allocate", problems[0])

    def test_cross_module_method_is_followed(self) -> None:
        problems = self.check_source(
            "fn void hot() { while (true) { item.apply(); } }",
            "fn void Item.apply(&self) { errors.tinit(); }",
        )
        self.assertEqual(len(problems), 1)

    def test_one_time_initialization_is_allowed(self) -> None:
        problems = self.check_source("fn void hot() { errors.tinit(); while (true) { tick(); } }")
        self.assertEqual(problems, [])

    def test_repeated_explicit_temp_allocator_fails(self) -> None:
        problems = self.check_source("fn void hot() { while (true) { errors.init(tmem, 1); } }")
        self.assertEqual(len(problems), 1)

    def test_direct_temp_array_obeys_same_scope_rule(self) -> None:
        problems = self.check_source("fn void hot() { while (true) { mem::temp_array(int, 16); } }")
        self.assertEqual(len(problems), 1)

    def test_error_only_exception_applies_to_next_allocation(self) -> None:
        problems = self.check_source(
            "fn void hot() { while (true) { if (failed) {\n"
            "// critical-path-lint: error-only\n"
            "mem::temp_array(int, 2);\n"
            "return;\n"
            "} errors.tinit(); } }"
        )
        self.assertEqual(len(problems), 1)
        self.assertIn("worker.c3:5:", problems[0])

    def test_caller_pool_protects_helper(self) -> None:
        problems = self.check_source(
            "fn void hot() { while (true) { @pool() { helper::allocate(); } } }",
            "fn void allocate() { errors.tinit(); }",
        )
        self.assertEqual(problems, [])

    def test_function_pool_protects_helper(self) -> None:
        problems = self.check_source(
            "fn void hot() { while (true) { helper::allocate(); } }",
            "fn void allocate() => @pool() { errors.tinit(); }",
        )
        self.assertEqual(problems, [])

    def test_batch_pool_allows_inner_bounded_loop(self) -> None:
        problems = self.check_source(
            "fn void hot() { while (true) { helper::batch(); } }",
            "fn void batch() { @pool() { for (int i = 0; i < 32; i++) { errors.tinit(); } } }",
        )
        self.assertEqual(problems, [])

    def test_pool_outside_loop_is_not_a_reset_boundary(self) -> None:
        problems = self.check_source("fn void hot() { @pool() { while (true) { errors.tinit(); } } }")
        self.assertEqual(len(problems), 1)

    def test_pool_outside_for_is_not_a_reset_boundary(self) -> None:
        problems = self.check_source("fn void hot() { @pool() { for (int i = 0; i < 100; i++) { errors.tinit(); } } }")
        self.assertEqual(len(problems), 1)

    def test_inner_pool_inside_loop_is_safe(self) -> None:
        problems = self.check_source("fn void hot() { @pool() { while (true) { @pool() { errors.tinit(); } } } }")
        self.assertEqual(problems, [])

    def test_pool_init_does_not_reset_each_iteration(self) -> None:
        problems = self.check_source("fn void hot() { @pool_init(mem, 4096) { while (true) { errors.tinit(); } } }")
        self.assertEqual(len(problems), 1)

    def test_ignores_comments_and_literals(self) -> None:
        problems = self.check_source('fn void hot() { while (true) { // errors.tinit();\n String s = "errors.tinit()"; String raw = `errors.tinit()`; } }')
        self.assertEqual(problems, [])

    def test_missing_root_is_a_failure(self) -> None:
        problems = self.check_source("fn void other() {}")
        self.assertEqual(problems, ["critical-path root missing: worker:hot"])


if __name__ == "__main__":
    unittest.main()
