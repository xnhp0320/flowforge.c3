#!/bin/sh
# Run inside Linux; build outputs and Python dependencies live outside the repo.
set -eu
repo=${1:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
tool_root=${FFG_TOOL_ROOT:-$HOME/.cache/flowforge-tools}
c3=${FFG_C3C:-$tool_root/c3-build/c3c}
python=${FFG_PYTHON:-$tool_root/venv/bin/python}
cd "$repo"
"$c3" build ffg --build-dir "$tool_root/ffg-build" --output-dir "$tool_root/ffg-bin"
"$c3" test ffg --build-dir "$tool_root/ffg-build" --output-dir "$tool_root/ffg-bin" --test-quiet
FFG_RUNTIME="$tool_root/ffg-bin/ffg" "$python" -m pytest tests/cli -q -p no:cacheprovider
"$python" -m pytest tests/e2e --backend pcap --runtime "$tool_root/ffg-bin/ffg" -q -p no:cacheprovider
sudo -n "$python" -m pytest tests/e2e --backend tap --runtime "$tool_root/ffg-bin/ffg" -q -p no:cacheprovider
ldd "$tool_root/ffg-bin/ffg"
if ldd "$tool_root/ffg-bin/ffg" | grep -q librte_; then
    echo 'Unexpected DPDK dependency in default build' >&2
    exit 1
fi
