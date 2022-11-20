FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake git python-is-python3 ninja-build subversion curl libz-dev clang

COPY . /repo
WORKDIR /repo/oclint-scripts
RUN ./make

RUN clang++ /repo/mayhem/fuzz_removeUnderscores.cpp -fsanitize=fuzzer,address -L /repo/build/oclint-rules/lib/util/ -lOCLintUtil -o /fuzz_removeUnderscores
