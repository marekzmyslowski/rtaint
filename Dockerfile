#
# Author: Marek Zmysłowski mzmyslowski@cycura.com
#
FROM ubuntu:18.04

# Installing dependencies
RUN apt-get update && apt-get install -y wget git make automake gcc python python3 python3-pip
RUN pip3 install setuptools

# Getting the Valgrind source code
WORKDIR /work
RUN wget https://sourceware.org/pub/valgrind/valgrind-3.15.0.tar.bz2
RUN tar jxvf valgrind-3.15.0.tar.bz2

# Getting the Taintgrind source code (it must be downloaded inside valgrind directory)
WORKDIR /work/valgrind-3.15.0
RUN git clone https://github.com/wmkhoo/taintgrind.git
WORKDIR /work/valgrind-3.15.0/taintgrind

# Building everything
RUN ./build_taintgrind.sh

# Getting and installing rtaint tool
WORKDIR /work
RUN git clone https://github.com/Cycura/rtaint.git
WORKDIR /work/rtaint
RUN python3 setup.py install