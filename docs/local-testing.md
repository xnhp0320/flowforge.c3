# Local testing

The default `ffg` target requires C3 0.8.4 and a C compiler, but no DPDK.
The source tree uses `@feat`, which older C3 releases do not understand.

## macOS

```sh
c3c build
c3c test
python3 -m venv /tmp/flowforge-tests
/tmp/flowforge-tests/bin/pip install -r tests/requirements.txt
/tmp/flowforge-tests/bin/python -m pytest tests/cli tests/e2e \
  --backend pcap --runtime "$PWD/build/ffg" -q
otool -L build/ffg
```

The PCAP adapter reuses the same packet cases and assertions as live TAP tests.
Runtime-only clone/split and receive cases are covered by unit tests and Linux
TAP tests rather than pretending that a file writer is a network interface.

## Lima

The existing `default` instance mounts this repository at the same host path.
It has Ubuntu ARM64, `/dev/net/tun`, `cc`, CMake, Python, and passwordless sudo.
Run `sh scripts/test-lima.sh` from macOS after preparing the toolchain below.
Use `LIMA_INSTANCE` to select another instance. All Linux binaries/build outputs
are placed under the Linux user's `~/.cache/flowforge-tools`, not the shared
repository. `FFG_TOOL_ROOT`, `FFG_C3C`, and `FFG_PYTHON` can override paths when
calling `scripts/test-linux.sh` inside Linux.

The runner executes C3 unit tests, CLI tests, PCAP cases, and privileged native
TAP cases. Tests explicitly marked DPDK-only are skipped. The TAP suite includes
multiworker TX/RX, clone/split, checksum verification, PCAP capture, persistent
device attachment, normal cleanup and SIGKILL cleanup.

### Toolchain preparation

The tested Linux C3 source revision is
`9a59869fc82825fe3f7d822725fcbee7dd4ee82f` from the locally mounted C3 repository.
The host prebuilt compiler reports version 0.8.4 but an older stale hash
`b402e98e`; rebuilding that hash produces 0.8.0 without `@feat`. Do not use that
hash to reproduce the host compiler.

Inside Lima, using its Linux home directory:

```sh
tool_root="$HOME/.cache/flowforge-tools"
mkdir -p "$tool_root"
git clone --no-hardlinks /Users/bytedance/src/c3c "$tool_root/c3c"
git -C "$tool_root/c3c" checkout 9a59869fc82825fe3f7d822725fcbee7dd4ee82f
cd "$tool_root"
apt download libzstd-dev libzstd1
for package in libzstd-dev_*.deb libzstd1_*.deb; do
    dpkg-deb -x "$package" sysroot
done
cmake -S c3c -B c3-build -DCMAKE_BUILD_TYPE=Release \
  -DC3_FETCH_LLVM=ON -DC3_LLVM_TAG=llvm_22.1.10 \
  -DCMAKE_PREFIX_PATH="$tool_root/sysroot/usr" \
  -Dzstd_LIBRARY="$tool_root/sysroot/usr/lib/aarch64-linux-gnu/libzstd.so"
cmake --build c3-build -j4
python3 -m venv "$tool_root/venv"
"$tool_root/venv/bin/pip" install -r /Users/bytedance/src/flowforge.c3/tests/requirements.txt
```

The tested LLVM artifact was the `.tar.gz` release asset from `llvm_22.1.10`
(its embedded LLVM version is 22.1.8). The newer C3 checkout requests `.tar.xz`;
both assets are published for that tag. Downloading/extracting Debian packages
above does not install system packages. C3 still needs the usual system C/C++
compiler and zlib development files, already present on this instance.

## DPDK regression

`c3c build ffg-dpdk` and `c3c test ffg-dpdk` use the original `/opt/dpdk`
Linux x86-64 installation layout. XSL uses `project.e2.json`. DPDK and XSL
C3 feature branches can also be type-checked without linking:

```sh
c3c compile-test src/*.c3 test/*.c3 -D DPDK -C
c3c compile-test src/*.c3 test/*.c3 -D DPDK -D XSL_DPDK -C
```

Lima has distro DPDK 24.11.2 in a different ARM64 layout. For that installation,
compile the two C shims with `pkg-config --cflags libdpdk`, then invoke
`c3c compile-test src/*.c3 test/*.c3 -D DPDK`, passing the shim objects and each
`pkg-config --libs libdpdk` flag via `-z`. This checks the real DPDK ABI and mbuf
metadata without changing the production target's installation paths.

The VM has four CPUs. Existing DPDK multiport cases request nine lcores and
need a suitable larger VM or explicit lcore mapping; native TAP workers are
ordinary threads and do not depend on EAL lcores.

On this VM, the real DPDK unit suite passes (255 tests) and 20 single-port
live cases pass. Three VXLAN cases fail with `rte_eth_dev_configure: Operation
not supported`; the same failures reproduce using unmodified `master`
`14e7ed2`, so they are an existing DPDK TAP offload limitation in this environment.
All corresponding native TAP VXLAN cases pass using software checksums.
