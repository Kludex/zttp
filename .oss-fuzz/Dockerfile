FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends xz-utils && \
    rm -rf /var/lib/apt/lists/*

ENV ZIG_VERSION=0.16.0
ENV ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
        -o /tmp/zig.tar.xz && \
    echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/zig.tar.xz -C /opt && \
    rm /tmp/zig.tar.xz && \
    ln -s "/opt/zig-x86_64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig

RUN git clone --depth 1 https://github.com/Kludex/zttp $SRC/zttp
WORKDIR $SRC/zttp
COPY build.sh $SRC/
