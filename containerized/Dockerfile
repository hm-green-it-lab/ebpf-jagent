FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openjdk-21-jdk \
      libcurl4-openssl-dev \
      make clang llvm gcc \
      libbpf-dev libelf-dev zlib1g-dev libc6-dev \
      linux-libc-dev linux-headers-$(uname -r) \
      linux-tools-common \
      linux-tools-$(uname -r) \
      linux-cloud-tools-$(uname -r) && \
    rm -rf /var/lib/apt/lists/*

RUN ln -s /usr/include/asm-generic /usr/include/asm

WORKDIR /opt/app

COPY containerized/java-app/ java-app/
RUN mkdir -p java-app/out \
 && javac -d java-app/out java-app/src/com/example/Main.java

COPY tool/ tool/
COPY tool/.env .env

WORKDIR /opt/app/tool
RUN make clean all

WORKDIR /opt/app
COPY containerized/entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
