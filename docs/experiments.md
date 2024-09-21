# README

This file describes how to run the experiments described in the paper.

## Experiment setup

All experiments were run in a docker image built using the [Dockerfile provided](../Dockerfile). Two instances of AFL++
were run with a limit of 8GB memory (4GB per instance) and 2 CPUs (1 CPU per instance).

## Historical fuzzer found vulnerabilities

We used 4 different packages widely used in previous fuzzing research: binutils, ffmpeg, gpac and libtiff. We describe
details of experiment for each package below. For each binary tested in all the packages, the initial seeds are present
in the [seeds](seeds) folder. All initial seeds are chosen from the [Unifuzz dataset](https://github.com/unifuzz/overview).
The fuzzing options for binary are chosen from Unifuzz dataset or past issues reported to the project.

### Package version details

|  Project | Version |                                Download URL                                |    Target binaries   |
|:--------:|:-------:|:--------------------------------------------------------------------------:|:--------------------:|
| binutils |   2.21  |           https://ftp.gnu.org/gnu/binutils/binutils-2.21.tar.bz2           | nm, objdump, readelf |
|  ffmpeg  |  0.10.1 |              https://ffmpeg.org/releases/ffmpeg-0.10.1.tar.bz2             |        ffmpeg        |
|   gpac   |  0.7.0  |        https://github.com/gpac/gpac/archive/refs/tags/v0.7.0.tar.gz        |        MP4Box        |
|  libtiff |  0.4.1  | https://gitlab.com/libtiff/libtiff/-/archive/v4.0.1/libtiff-v4.0.1.tar.bz2 |        tiffcp        |

### binutils

Build instructions

```bash
CC=`which afl-clang-lto` CXX=`which afl-clang-lto++` LDFLAGS="-Wl,-z,norelro -no-pie" ./configure --prefix=$PWD/install
make -j
make install
```

Fuzzing options

nm: `-A -a -l -S -s --special-syms --synthetic -D @@`

objdump: `-s -h -p -a --dwarf -WL -G -D -g @@`

readelf: `-w @@`

### ffmpeg

Build instructions

```bash
./configure --cc=afl-clang-lto --cxx=afl-clang-lto++ --extra-ldflags="-Wl,-z,norelro -no-pie" --disable-asm --disable-pthreads --disable-stripping --prefix=$PWD/install
make -j
make install
```

Fuzzing options: `-y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null`

### gpac

Build instructions

```bash
./configure --cc=afl-clang-lto --cxx=afl-clang-lto++ --enable-static-bin --static-mp4box --extra-ldflags="-no-pie" --prefix=$PWD/install
make -j
make install
```

Fuzzing options for MP4Box: `-info @@`

### libtiff

Build instructions

```bash
$ CC=`which afl-clang-lto` CXX=`which afl-clang-lto++` LDFLAGS="-Wl,-z,norelro -no-pie" ./configure --prefix=$PWD/install --enable-shared=no
$ make -j
$ make install
```

Fuzzing options for tiffcp: `-i @@ /tmp/blah`.

## OSS-Fuzz experiments

We first find reproducible, fuzz blocking crashes OSS-Fuzz discovered using libfuzzer based harnesses using the query
`label:Fuzz-Blocker label:Reproducible label:Engine-libfuzzer` and then manually analyzed the list identify crashes that
target C/C++ programs and can be reproduced when the fuzz harness is built for AFL++ with no sanitizers. The final
filtered set of crash reports are used as the first crash FlakJack has to bypass.