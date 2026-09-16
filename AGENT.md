# E2 test workaround

On the Lima E2 environment, run C3 tests with `-O0`:

```sh
c3c test ffg -O0
```

The E2 XSL DPDK toolchain can repeatedly panic when tests are built with its
default optimization level. `-O0` is the required workaround for E2 test runs;
this does not apply to the normal macOS local test workflow.
