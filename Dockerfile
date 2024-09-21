FROM aflplusplus/aflplusplus:v4.09c

RUN apt update && apt install -y pigz nasm gdb
RUN pip3 install ROPgadget==7.3 pwntools==4.11.0 angr==9.2.81
RUN pip3 install git+https://github.com/angr/phuzzer@232ca58
RUN pip3 install git+https://github.com/mechaphish/povsim@78c192c
RUN pip3 install git+https://github.com/angr/tracer@4057000
RUN pip3 install git+https://github.com/mechaphish/compilerex@6d49822
RUN pip3 install git+https://github.com/angr/fidget@2dc069a
RUN pip3 install git+https://github.com/angr/patcherex@82242e3
ENV AFL_PATH="/usr/local/bin"
ENV AFL_IGNORE_SEED_PROBLEMS="1"
COPY . /flakjack
RUN pip3 install -e /flakjack
WORKDIR /root
