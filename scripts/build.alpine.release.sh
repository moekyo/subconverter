#!/bin/bash
set -euo pipefail

LOG_DIR="${BUILD_LOG_DIR:-/tmp/subconverter-build}"
HEARTBEAT_SECONDS="${BUILD_HEARTBEAT_SECONDS:-15}"
mkdir -p "$LOG_DIR"

step() {
    printf '\n[subconverter-build] %s\n' "$1"
}

log_path() {
    local name="$1"
    name="${name//[^A-Za-z0-9._-]/_}"
    printf '%s/%s.log' "$LOG_DIR" "$name"
}

show_failure() {
    local label="$1"
    local status="$2"
    local logfile="$3"
    printf '\n[subconverter-build] FAILED: %s (exit %s)\n' "$label" "$status" >&2
    printf '[subconverter-build] Last log lines:\n' >&2
    tail -n 120 "$logfile" >&2 || true
}

run_quiet() {
    local label="$1"
    shift
    local logfile
    local started
    local finished
    local status
    logfile="$(log_path "$label")"
    started="$(date +%s)"
    step "$label"
    if "$@" >"$logfile" 2>&1; then
        finished="$(date +%s)"
        printf '[subconverter-build] done: %s (%ss)\n' "$label" "$((finished - started))"
        rm -f "$logfile"
        return 0
    fi
    status=$?
    show_failure "$label" "$status" "$logfile"
    return "$status"
}

run_with_heartbeat() {
    local label="$1"
    shift
    local logfile
    local started
    local now
    local pid
    local status
    logfile="$(log_path "$label")"
    started="$(date +%s)"
    step "$label"

    "$@" >"$logfile" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        sleep "$HEARTBEAT_SECONDS"
        if kill -0 "$pid" 2>/dev/null; then
            now="$(date +%s)"
            printf '[subconverter-build] working: %s (%ss elapsed)\n' "$label" "$((now - started))"
        fi
    done

    if wait "$pid"; then
        now="$(date +%s)"
        printf '[subconverter-build] done: %s (%ss)\n' "$label" "$((now - started))"
        rm -f "$logfile"
        return 0
    fi
    status=$?
    show_failure "$label" "$status" "$logfile"
    return "$status"
}

run_quiet "Install build toolchain" \
    apk add --no-cache gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 py3-pip
run_quiet "Install static build dependencies" \
    apk add --no-cache mbedtls-dev mbedtls-static zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static brotli-dev brotli-static zstd-dev zstd-static libpsl-dev libpsl-static

run_quiet "Fetch curl 8.21.0" \
    git -c advice.detachedHead=false clone --quiet https://github.com/curl/curl --depth=1 --branch curl-8_21_0
pushd curl >/dev/null
run_quiet "Configure curl" \
    cmake -DCURL_USE_MBEDTLS=ON -DHTTP_ONLY=ON -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCURL_USE_LIBSSH2=OFF -DBUILD_CURL_EXE=OFF -DCURL_ZSTD=ON -DCURL_BROTLI=ON -DUSE_NGHTTP2=OFF -DUSE_LIBIDN2=OFF -DCURL_USE_LIBPSL=OFF .
run_with_heartbeat "Build curl" make install -j2
popd >/dev/null

run_quiet "Fetch yaml-cpp" \
    git clone --quiet https://github.com/jbeder/yaml-cpp --depth=1
pushd yaml-cpp >/dev/null
run_quiet "Configure yaml-cpp" \
    cmake -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF .
run_with_heartbeat "Build yaml-cpp" make install -j3
popd >/dev/null

run_quiet "Fetch QuickJS++" \
    git clone --quiet https://github.com/ftk/quickjspp --depth=1
pushd quickjspp >/dev/null
run_quiet "Configure QuickJS++" cmake -DCMAKE_BUILD_TYPE=Release .
run_with_heartbeat "Build QuickJS" make quickjs -j3
run_quiet "Install QuickJS" install -d /usr/lib/quickjs/
run_quiet "Install QuickJS library" install -m644 quickjs/libquickjs.a /usr/lib/quickjs/
run_quiet "Install QuickJS headers directory" install -d /usr/include/quickjs/
run_quiet "Install QuickJS headers" install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/
run_quiet "Install QuickJS++ header" install -m644 quickjspp.hpp /usr/include/
popd >/dev/null

run_quiet "Fetch libcron" \
    git clone --quiet https://github.com/PerMalmberg/libcron --depth=1
pushd libcron >/dev/null
run_quiet "Fetch libcron submodules" git submodule update --init --quiet
run_quiet "Configure libcron" cmake -DCMAKE_BUILD_TYPE=Release .
run_with_heartbeat "Build libcron" make libcron install -j3
popd >/dev/null

run_quiet "Fetch toml11 v4.4.0" \
    git -c advice.detachedHead=false clone --quiet https://github.com/ToruNiina/toml11 --branch=v4.4.0 --depth=1
pushd toml11 >/dev/null
run_quiet "Configure toml11" cmake -DCMAKE_CXX_STANDARD=11 .
run_with_heartbeat "Install toml11" make install -j4
popd >/dev/null

export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
run_quiet "Configure subconverter" cmake -DCMAKE_BUILD_TYPE=Release .
run_with_heartbeat "Compile subconverter" make -j3
rm -f subconverter
mapfile -t SUBCONVERTER_OBJECTS < <(find CMakeFiles/subconverter.dir/src/ -name '*.o')
run_with_heartbeat "Create static subconverter binary" \
    g++ -o base/subconverter "${SUBCONVERTER_OBJECTS[@]}" \
    -static -lpcre2-8 -lyaml-cpp -L/usr/lib64 -lcurl -lmbedtls -lmbedcrypto -lmbedx509 \
    -lz -lbrotlidec -lbrotlicommon -lzstd -l:quickjs/libquickjs.a -llibcron -O3 -s

if [ "${SKIP_RULE_UPDATE:-0}" = "1" ]; then
    step "Bundled rule refresh"
    printf '[subconverter-build] skipped (SKIP_RULE_UPDATE=1)\n'
else
    run_quiet "Install rule refresh dependency" pip install --break-system-packages gitpython
    run_with_heartbeat "Refresh bundled third-party rules" \
        python3 scripts/update_rules.py -c scripts/rules_config.conf
fi

step "Prepare runtime bundle"
pushd base >/dev/null
chmod +rx subconverter
chmod +r ./*
popd >/dev/null
mv base subconverter
printf '[subconverter-build] runtime bundle ready\n'
