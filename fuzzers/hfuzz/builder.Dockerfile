# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        python3-dev \
        python3-setuptools \
        automake \
        cmake \
        git \
        flex \
        bison \
        libglib2.0-dev \
        libpixman-1-dev \
        cargo \
        libgtk-3-dev \
        # for QEMU mode
        ninja-build \
        gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev \
        libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev

# Download FOX
RUN git clone https://github.com/abbott-xie/AFLplusplus.git /fox
RUN git -C /fox checkout instrument_specific_4.30c

# Download Ztaint
RUN git clone https://github.com/abbott-xie/AFLplusplus.git /ztaint
RUN git -C /ztaint checkout ada_taint_log_v4.30c

# Download afl++.
RUN git clone -b dev https://github.com/AFLplusplus/AFLplusplus /afl_vanilla  && \
    cd /afl_vanilla  && \
    git checkout tags/v4.30c || \
    true

# Build without Python support as we don't need it.
# Set AFL_NO_X86 to skip flaky tests.
RUN cd /afl_vanilla && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang-15 AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make && \
    cp utils/aflpp_driver/libAFLDriver.a /

RUN cd /fox && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang-15 AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make && \
    cp utils/aflpp_driver/libAFLDriver.a /

RUN cd /ztaint && \
    unset CFLAGS CXXFLAGS && \
    export CC=clang-15 AFL_NO_X86=1 && \
    PYTHON_INCLUDE=/ make && \
    cp utils/aflpp_driver/libAFLDriver.a /