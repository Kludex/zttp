FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends xz-utils && \
    rm -rf /var/lib/apt/lists/*

ENV ZIG_VERSION=0.16.0
RUN curl -sSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
        | tar -xJ -C /opt && \
    ln -s "/opt/zig-x86_64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

RUN git clone --depth 1 https://github.com/Kludex/zttp $SRC/zttp
WORKDIR $SRC/zttp
COPY build.sh $SRC/
