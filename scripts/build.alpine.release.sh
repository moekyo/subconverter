#!/bin/bash
set -euo pipefail

LOG_DIR="${BUILD_LOG_DIR:-/tmp/subconverter-build}"
HEARTBEAT_SECONDS="${BUILD_HEARTBEAT_SECONDS:-15}"
NETWORK_RETRIES="${BUILD_NETWORK_RETRIES:-3}"
NETWORK_RETRY_DELAY_SECONDS="${BUILD_NETWORK_RETRY_DELAY_SECONDS:-5}"
NETWORK_ATTEMPT_TIMEOUT_SECONDS="${BUILD_NETWORK_ATTEMPT_TIMEOUT_SECONDS:-600}"
DEPS_ROOT="${BUILD_DEPS_ROOT:-/opt/subconverter-deps-src}"
MODE="${1:-all}"
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
    else
        status=$?
        show_failure "$label" "$status" "$logfile"
        return "$status"
    fi
}

run_with_heartbeat() {
    local label="$1"
    shift
    local logfile
    local started
    local now
    local next_heartbeat
    local pid
    local status
    logfile="$(log_path "$label")"
    started="$(date +%s)"
    next_heartbeat=$((started + HEARTBEAT_SECONDS))
    step "$label"

    "$@" >"$logfile" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        sleep 1
        now="$(date +%s)"
        if [ "$now" -ge "$next_heartbeat" ] && kill -0 "$pid" 2>/dev/null; then
            printf '[subconverter-build] working: %s (%ss elapsed)\n' "$label" "$((now - started))"
            next_heartbeat=$((now + HEARTBEAT_SECONDS))
        fi
    done

    if wait "$pid"; then
        now="$(date +%s)"
        printf '[subconverter-build] done: %s (%ss)\n' "$label" "$((now - started))"
        rm -f "$logfile"
        return 0
    else
        status=$?
        show_failure "$label" "$status" "$logfile"
        return "$status"
    fi
}

require_positive_integer() {
    local name="$1"
    local value="$2"
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        printf '[subconverter-build] invalid %s=%s; expected positive integer\n' "$name" "$value" >&2
        exit 2
    fi
}

run_network_with_retry() {
    local label="$1"
    shift
    local attempt=1

    while [ "$attempt" -le "$NETWORK_RETRIES" ]; do
        if run_with_heartbeat \
            "$label (attempt $attempt/$NETWORK_RETRIES)" \
            timeout "$NETWORK_ATTEMPT_TIMEOUT_SECONDS" "$@"; then
            return 0
        fi
        if [ "$attempt" -ge "$NETWORK_RETRIES" ]; then
            printf '[subconverter-build] network step exhausted %s attempts: %s\n' \
                "$NETWORK_RETRIES" "$label" >&2
            return 1
        fi
        printf '[subconverter-build] retrying: %s in %ss\n' \
            "$label" "$NETWORK_RETRY_DELAY_SECONDS" >&2
        sleep "$NETWORK_RETRY_DELAY_SECONDS"
        attempt=$((attempt + 1))
    done
}

clone_repo() {
    local label="$1"
    local destination="$2"
    shift 2

    mkdir -p "$(dirname "$destination")"
    rm -rf "$destination"
    run_network_with_retry \
        "$label" \
        git \
        -c http.version=HTTP/1.1 \
        -c http.lowSpeedLimit=1024 \
        -c http.lowSpeedTime=60 \
        clone "$@" "$destination"
}

build_dependencies() {
    require_positive_integer BUILD_HEARTBEAT_SECONDS "$HEARTBEAT_SECONDS"
    require_positive_integer BUILD_NETWORK_RETRIES "$NETWORK_RETRIES"
    require_positive_integer BUILD_NETWORK_RETRY_DELAY_SECONDS "$NETWORK_RETRY_DELAY_SECONDS"
    require_positive_integer BUILD_NETWORK_ATTEMPT_TIMEOUT_SECONDS "$NETWORK_ATTEMPT_TIMEOUT_SECONDS"

    rm -rf "$DEPS_ROOT"
    mkdir -p "$DEPS_ROOT"

    run_network_with_retry "Install build toolchain" \
        apk add --no-cache gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 py3-pip
    run_network_with_retry "Install static build dependencies" \
        apk add --no-cache mbedtls-dev mbedtls-static zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static brotli-dev brotli-static zstd-dev zstd-static libpsl-dev libpsl-static

    clone_repo "Fetch curl 8.21.0" "$DEPS_ROOT/curl" \
        --quiet --depth=1 --branch curl-8_21_0 https://github.com/curl/curl
    pushd "$DEPS_ROOT/curl" >/dev/null
    run_quiet "Configure curl" \
        cmake -DCURL_USE_MBEDTLS=ON -DHTTP_ONLY=ON -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF -DCURL_USE_LIBSSH2=OFF -DBUILD_CURL_EXE=OFF -DCURL_ZSTD=ON -DCURL_BROTLI=ON -DUSE_NGHTTP2=OFF -DUSE_LIBIDN2=OFF -DCURL_USE_LIBPSL=OFF .
    run_with_heartbeat "Build curl" make install -j2
    popd >/dev/null

    clone_repo "Fetch yaml-cpp" "$DEPS_ROOT/yaml-cpp" \
        --quiet --depth=1 https://github.com/jbeder/yaml-cpp
    pushd "$DEPS_ROOT/yaml-cpp" >/dev/null
    run_quiet "Configure yaml-cpp" \
        cmake -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF .
    run_with_heartbeat "Build yaml-cpp" make install -j3
    popd >/dev/null

    clone_repo "Fetch QuickJS++" "$DEPS_ROOT/quickjspp" \
        --quiet --depth=1 https://github.com/ftk/quickjspp
    pushd "$DEPS_ROOT/quickjspp" >/dev/null
    run_quiet "Configure QuickJS++" cmake -DCMAKE_BUILD_TYPE=Release .
    run_with_heartbeat "Build QuickJS" make quickjs -j3
    run_quiet "Install QuickJS" install -d /usr/lib/quickjs/
    run_quiet "Install QuickJS library" install -m644 quickjs/libquickjs.a /usr/lib/quickjs/
    run_quiet "Install QuickJS headers directory" install -d /usr/include/quickjs/
    run_quiet "Install QuickJS headers" install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/
    run_quiet "Install QuickJS++ header" install -m644 quickjspp.hpp /usr/include/
    popd >/dev/null

    # libcron's repository-level CMake unconditionally adds test/, whose Catch2
    # submodule is irrelevant to the production static library. Fetch only the
    # date submodule used by libcron itself, then configure the library subtree
    # directly so a test-only GitHub dependency cannot block production builds.
    clone_repo "Fetch libcron production dependencies" "$DEPS_ROOT/libcron" \
        --quiet --depth=1 \
        --recurse-submodules=libcron/externals/date \
        --shallow-submodules \
        https://github.com/PerMalmberg/libcron
    pushd "$DEPS_ROOT/libcron" >/dev/null
    run_quiet "Configure libcron" \
        cmake -S libcron -B build -DCMAKE_BUILD_TYPE=Release
    run_with_heartbeat "Build libcron" \
        cmake --build build --target libcron --parallel 3
    run_quiet "Install libcron" bash -c '
        install -d /usr/local/lib /usr/local/include
        install -m644 libcron/out/Release/liblibcron.a /usr/local/lib/liblibcron.a
        rm -rf /usr/local/include/libcron /usr/local/include/date
        cp -R libcron/include/libcron /usr/local/include/libcron
        cp -R libcron/externals/date/include/date /usr/local/include/date
    '
    popd >/dev/null

    clone_repo "Fetch toml11 v4.4.0" "$DEPS_ROOT/toml11" \
        --quiet --depth=1 --branch v4.4.0 https://github.com/ToruNiina/toml11
    pushd "$DEPS_ROOT/toml11" >/dev/null
    run_quiet "Configure toml11" cmake -DCMAKE_CXX_STANDARD=11 .
    run_with_heartbeat "Install toml11" make install -j4
    popd >/dev/null

    rm -rf "$DEPS_ROOT"
    printf '[subconverter-build] dependency layer ready\n'
}

build_project() {
    require_positive_integer BUILD_HEARTBEAT_SECONDS "$HEARTBEAT_SECONDS"

    export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
    run_quiet "Configure subconverter" cmake -DCMAKE_BUILD_TYPE=Release .
    run_with_heartbeat "Compile subconverter" make -j3
    rm -f subconverter
    mapfile -t SUBCONVERTER_OBJECTS < <(find CMakeFiles/subconverter.dir/src/ -name '*.o')
    run_with_heartbeat "Create static subconverter binary" \
        g++ -o base/subconverter "${SUBCONVERTER_OBJECTS[@]}" \
        -static -lpcre2-8 -lyaml-cpp -L/usr/lib64 -L/usr/local/lib -lcurl -lmbedtls -lmbedcrypto -lmbedx509 \
        -lz -lbrotlidec -lbrotlicommon -lzstd -l:quickjs/libquickjs.a -llibcron -O3 -s

    if [ "${SKIP_RULE_UPDATE:-0}" = "1" ]; then
        step "Bundled rule refresh"
        printf '[subconverter-build] skipped (SKIP_RULE_UPDATE=1)\n'
    else
        run_network_with_retry "Install rule refresh dependency" \
            pip install --break-system-packages gitpython
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
}

case "$MODE" in
    dependencies)
        build_dependencies
        ;;
    project)
        build_project
        ;;
    all)
        build_dependencies
        build_project
        ;;
    -h|--help)
        cat <<'EOF'
Usage: bash scripts/build.alpine.release.sh [dependencies|project|all]

Modes:
  dependencies  Install and build third-party static dependencies only.
  project       Build/link subconverter using already-installed dependencies.
  all           Run both phases (default; backward compatible).

Network controls:
  BUILD_NETWORK_RETRIES                  default 3
  BUILD_NETWORK_RETRY_DELAY_SECONDS      default 5
  BUILD_NETWORK_ATTEMPT_TIMEOUT_SECONDS  default 600
  BUILD_HEARTBEAT_SECONDS                default 15
EOF
        ;;
    *)
        printf '[subconverter-build] unknown mode: %s\n' "$MODE" >&2
        exit 2
        ;;
esac
