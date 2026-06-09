#!/bin/bash -eu

# Build the coverage-instrumented Zig object, then let OSS-Fuzz's clang compile
# the C shim and link it against $LIB_FUZZING_ENGINE. The shim registers the
# Zig object's SanitizerCoverage counters with the engine (see fuzz/target.c).

zig build fuzz-obj

# The shim is pure glue: compile it with no coverage of its own (-fno-sanitize-
# coverage=...) so the engine sees exactly one instrumented module - the parser.
# lld handles Zig's DWARF and the local-dynamic TLS relocations that the base
# image's GNU ld truncates.
$CC $CFLAGS -fno-sanitize-coverage=edge,trace-pc-guard,trace-cmp,indirect-calls,8bit-counters,inline-8bit-counters,pc-table \
    -c fuzz/target.c -o "$WORK/zttp_fuzz_shim.o"
$CXX $CXXFLAGS -fuse-ld=lld "$WORK/zttp_fuzz_shim.o" zig-out/bin/zttp_fuzz_reader.o \
    $LIB_FUZZING_ENGINE -o "$OUT/zttp_fuzz_reader"

# Seed corpus: a handful of valid HTTP messages so coverage starts structured.
mkdir -p "$WORK/seed"
printf 'GET / HTTP/1.1\r\nHost: a\r\n\r\n' > "$WORK/seed/get"
printf 'POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello' > "$WORK/seed/post"
printf 'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n' > "$WORK/seed/chunked"
printf 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi' > "$WORK/seed/response"
zip -j "$OUT/zttp_fuzz_reader_seed_corpus.zip" "$WORK"/seed/*
