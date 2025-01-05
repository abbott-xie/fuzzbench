# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# ...

import os
import shutil
import subprocess
import sys

from fuzzers import utils

def is_benchmark(name):
    """Check if the benchmark contains the string |name|."""
    benchmark = os.getenv("BENCHMARK", None)
    return benchmark is not None and name in benchmark


def install(package):
    """Install a Python package with pip."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])


def install_all():
    """Install all required Python dependencies."""
    packages = [
        "asttokens==2.2.1", "backcall==0.2.0", "decorator==5.1.1",
        "executing==1.2.0", "greenstalk==2.0.2", "ipdb==0.13.13",
        "ipython==8.12.2", "jedi==0.18.2", "networkit==10.1", "numpy==1.24.4",
        "parso==0.8.3", "pexpect==4.8.0", "pickleshare==0.7.5",
        "prompt-toolkit==3.0.39", "psutil==5.9.5", "ptyprocess==0.7.0",
        "pure-eval==0.2.2", "Pygments==2.15.1", "PyYAML==5.3.1",
        "scipy==1.10.1", "six==1.16.0", "stack-data==0.6.2", "tabulate==0.9.0",
        "tomli==2.0.1", "traitlets==5.9.0", "typing-extensions==4.7.1",
        "wcwidth==0.2.6",
        # 额外需求
        "pyelftools==0.30"
    ]
    for p in packages:
        install(p)


def prepare_build_environment():
    """
    仅对 benchmark 做一些通用修复。
    不在这里设置 CC/CXX/FUZZER_LIB，因为我们会分别在 build_fox_binary、build_ztaint_binary、
    build_vanilla_binary、build_cmplog_binary 中对其设置。
    """
    if is_benchmark("mbedtls"):
        file_path = os.path.join(os.getenv("SRC"), "mbedtls", "library", "CMakeLists.txt")
        if os.path.isfile(file_path):
            subst_cmd = r"sed -i 's/\(-Wdocumentation\)//g' " + file_path
            subprocess.check_call(subst_cmd, shell=True)

    if is_benchmark("openthread"):
        mbed_cmake_one = os.path.join(
            os.getenv("SRC"),
            "openthread", "third_party", "mbedtls", "repo",
            "library", "CMakeLists.txt")
        mbed_cmake_two = os.path.join(
            os.getenv("SRC"),
            "openthread", "third_party", "mbedtls", "repo",
            "CMakeLists.txt")
        if os.path.isfile(mbed_cmake_one):
            subst_cmd = r"sed -i 's/\(-Wdocumentation\)//g' " + mbed_cmake_one
            subprocess.check_call(subst_cmd, shell=True)
        if os.path.isfile(mbed_cmake_two):
            subst_cmd = r"sed -i 's/\(-Werror\)//g' " + mbed_cmake_two
            subprocess.check_call(subst_cmd, shell=True)


def get_fox_build_directory(target_directory):
    """Return path to fox build directory."""
    return os.path.join(target_directory, "fox")


def get_ztaint_build_directory(target_directory):
    """Return path to ztaint build directory."""
    return os.path.join(target_directory, "ztaint")


def get_vanilla_build_directory(target_directory):
    """Return path to vanilla build directory."""
    return os.path.join(target_directory, "vanilla")


def get_cmplog_build_directory(target_directory):
    """Return path to cmplog build directory."""
    return os.path.join(target_directory, "cmplog")

def get_setcover_build_directory(target_directory):
    return os.path.join(target_directory, "setcover");

def get_libafl_build_directory(target_directory):
    """Return path to libafl build directory."""
    return os.path.join(target_directory, "libafl")

def build_fox_binary():
    """
    Build FOX-instrumented binary：
      1) 清理 /dev/shm/*
      2) 切换 CC/CXX/FUZZER_LIB => /fox
      3) 创建 fox 目录
      4) 调用 build_benchmark
      5) 执行 gen_graph_no_gllvm_15.py (切换到 outdir)
      6) 若成功，把产物复制回 /out
      7) 把 FOX 生成的 br_node_id_2_cmp_type 等文件也复制到 /out
    """
    print("[build_fox_binary] Building FOX instrumentation.")
    is_build_failed = False

    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    fuzz_target = os.getenv("FUZZ_TARGET")
    out_dir = os.getenv("OUT")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")

    os.environ["CC"] = "/fox/afl-clang-fast"
    os.environ["CXX"] = "/fox/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/fox/libAFLDriver.a"

    os.environ["AFL_LLVM_DICT2FILE"] = os.path.join(out_dir, "keyval.dict")
    os.environ["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"

    fox_dir = get_fox_build_directory(out_dir)
    if not os.path.exists(fox_dir):
        os.mkdir(fox_dir)

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = fox_dir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(fox_dir, os.path.basename(fuzz_target))

        try:
            utils.build_benchmark(env=new_env)

            # 拷贝中间件信息
            for f in ["br_src_map", "strcmp_err_log", "instrument_meta_data"]:
                tmp_path = os.path.join("/dev/shm", f)
                if os.path.exists(tmp_path):
                    shutil.copy(tmp_path, os.path.join(fox_dir, f))

            # 在 FOX 编译结束之后，需要把下列文件复制到 /out：
            # br_node_id_2_cmp_type、border_edges、max_border_edge_id、
            # max_br_dist_edge_id、border_edges_cache。
            # 假设它们和上面类似，均产自 /dev/shm/
            FOX_FILES = [
                "br_node_id_2_cmp_type",
                "border_edges",
                "max_border_edge_id",
                "max_br_dist_edge_id",
                "border_edges_cache"
            ]
            for f in FOX_FILES:
                fox_file_path = os.path.join("/dev/shm", f)
                if os.path.exists(fox_file_path):
                    shutil.copy(fox_file_path, os.path.join(fox_dir, f))

            # 切换到 fox_dir 调用 gen_graph_no_gllvm_15.py
            graph_script = "/fox/gen_graph_no_gllvm_15.py"
            old_dir = os.getcwd()
            try:
                os.chdir(fox_dir)
                final_fuzz_bin = new_env["FUZZ_TARGET"]
                subprocess.check_call([
                    "python3", graph_script, final_fuzz_bin, "instrument_meta_data"
                ])
            finally:
                os.chdir(old_dir)

        except subprocess.CalledProcessError:
            print("[build_fox_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    # 如果编译成功，把 fox_dir 下的 fuzz_target 拷贝回 out_dir
    if (not is_build_failed) and fuzz_target:
        built_bin = os.path.join(fox_dir, os.path.basename(fuzz_target))
        if os.path.exists(built_bin):
            shutil.copy(built_bin, os.path.join(out_dir, "fox_" + os.path.basename(fuzz_target)))

        # 同时也把 FOX_FILES 复制到 /out (如果它们在 fox_dir 里)
        FOX_FILES = [
            "br_node_id_2_cmp_type",
            "border_edges",
            "max_border_edge_id",
            "max_br_dist_edge_id",
            "border_edges_cache"
        ]
        for f in FOX_FILES:
            in_build_dir = os.path.join(fox_dir, f)
            if os.path.exists(in_build_dir):
                shutil.copy(in_build_dir, os.path.join(out_dir, f))

    return (not is_build_failed)


def build_ztaint_binary():
    """
    Build ZTaint-instrumented binary：
      1) 清理 /dev/shm/*
      2) 切换 CC/CXX/FUZZER_LIB => /ztaint
      3) 创建 ztaint 目录
      4) 调用 build_benchmark
      5) 执行 gen_graph_no_gllvm_15.py (切换到 ztaint_dir)
      6) 若成功，把产物复制回 /out
      7) 把 ZTaint 生成的 ztaint_br_node_id_2_cmp_type 等文件也复制到 /out
    """
    print("[build_ztaint_binary] Building ZTaint instrumentation.")
    is_build_failed = False

    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    fuzz_target = os.getenv("FUZZ_TARGET")
    out_dir = os.getenv("OUT")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")

    os.environ["CC"] = "/ztaint/afl-clang-fast"
    os.environ["CXX"] = "/ztaint/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/ztaint/libAFLDriver.a"

    os.environ["AFL_LLVM_DICT2FILE"] = os.path.join(out_dir, "keyval.dict")
    os.environ["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"

    ztaint_dir = get_ztaint_build_directory(out_dir)
    if not os.path.exists(ztaint_dir):
        os.mkdir(ztaint_dir)

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = ztaint_dir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(ztaint_dir, os.path.basename(fuzz_target))

        try:
            utils.build_benchmark(env=new_env)

            for f in ["br_src_map", "strcmp_err_log", "instrument_meta_data"]:
                tmp_path = os.path.join("/dev/shm", f)
                if os.path.exists(tmp_path):
                    shutil.copy(tmp_path, os.path.join(ztaint_dir, f))

            graph_script = "/ztaint/gen_graph_no_gllvm_15.py"
            old_dir = os.getcwd()
            try:
                os.chdir(ztaint_dir)
                final_fuzz_bin = new_env["FUZZ_TARGET"]
                subprocess.check_call(["python3", graph_script,
                                       final_fuzz_bin, "instrument_meta_data"])
            finally:
                os.chdir(old_dir)

        except subprocess.CalledProcessError:
            print("[build_ztaint_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    if (not is_build_failed) and fuzz_target:
        built_bin = os.path.join(ztaint_dir, os.path.basename(fuzz_target))
        if os.path.exists(built_bin):
            shutil.copy(built_bin, os.path.join(out_dir, "ztaint_" + os.path.basename(fuzz_target)))

        # 同时也将 ZTAINT_FILES 复制到 /out
        ZTAINT_FILES = [
            "ztaint_br_node_id_2_cmp_type",
            "ztaint_border_edges",
            "ztaint_max_border_edge_id",
            "ztaint_max_br_dist_edge_id",
            "ztaint_border_edges_cache"
        ]
        for f in ZTAINT_FILES:
            in_build_dir = os.path.join(ztaint_dir, f)
            if os.path.exists(in_build_dir):
                shutil.copy(in_build_dir, os.path.join(out_dir, f))

    return (not is_build_failed)


def build_vanilla_binary():
    print("[build_vanilla_binary] Building vanilla instrumentation.")
    is_build_failed = False

    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    fuzz_target = os.getenv("FUZZ_TARGET")
    out_dir = os.getenv("OUT")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")

    os.environ["CC"] = "/afl_vanilla/afl-clang-fast"
    os.environ["CXX"] = "/afl_vanilla/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/afl_vanilla/libAFLDriver.a"

    vanilla_dir = get_vanilla_build_directory(out_dir)
    if not os.path.exists(vanilla_dir):
        os.mkdir(vanilla_dir)

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = vanilla_dir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(vanilla_dir, os.path.basename(fuzz_target))

        try:
            utils.build_benchmark(env=new_env)
        except subprocess.CalledProcessError:
            print("[build_vanilla_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    if (not is_build_failed) and fuzz_target:
        built_bin = os.path.join(vanilla_dir, os.path.basename(fuzz_target))
        if os.path.exists(built_bin):
            shutil.copy(built_bin, os.path.join(out_dir, os.path.basename(fuzz_target)))

    return (not is_build_failed)


def build_cmplog_binary():
    print("[build_cmplog_binary] Building cmplog instrumentation.")
    is_build_failed = False

    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    fuzz_target = os.getenv("FUZZ_TARGET")
    out_dir = os.getenv("OUT")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")
    old_cmp = os.environ.get("AFL_LLVM_CMPLOG")

    os.environ["CC"] = "/afl_vanilla/afl-clang-fast"
    os.environ["CXX"] = "/afl_vanilla/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/afl_vanilla/libAFLDriver.a"
    os.environ["AFL_LLVM_CMPLOG"] = "1"

    cmplog_dir = get_cmplog_build_directory(out_dir)
    if not os.path.exists(cmplog_dir):
        os.mkdir(cmplog_dir)

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = cmplog_dir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(cmplog_dir, os.path.basename(fuzz_target))

        try:
            utils.build_benchmark(env=new_env)
        except subprocess.CalledProcessError:
            print("[build_cmplog_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib
            if old_cmp is not None:
                os.environ["AFL_LLVM_CMPLOG"] = old_cmp
            else:
                os.environ.pop("AFL_LLVM_CMPLOG", None)

    if (not is_build_failed) and fuzz_target:
        built_bin = os.path.join(cmplog_dir, os.path.basename(fuzz_target))
        if os.path.exists(built_bin):
            shutil.copy(
                built_bin,
                os.path.join(out_dir, "cmplog_" + os.path.basename(fuzz_target))
            )

    return (not is_build_failed)

def build_setcover_binary():

    is_build_failed = False
    print("[build_setcover_binary] Building setcover instrumentation.")

    out_dir = os.getenv("OUT")
    pwd = os.getcwd()
    # src = os.path.join(out_dir, "setcover_target_bin")
    src = os.getenv("SRC")
    work = os.getenv("WORK")

    fuzz_target = os.getenv("FUZZ_TARGET")

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_cflags = os.environ.get("CFLAGS")
    old_cxxflags = os.environ.get("CXXFLAGS")
    old_lib = os.environ.get("FUZZER_LIB")
    old_cmp = os.environ.get("AFL_LLVM_CMPLOG")


    os.environ["CC"] = "/setcover/afl-clang-fast"
    os.environ["CXX"] = "/setcover/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/afl_vanilla/libAFLDriver.a"
    # macros = "-DAFL_CFG_PATH=\\\"setcover_sandcov_cfg\\\""
    # os.environ["CFLAGS"] = macros
    # os.environ["CXXFLAGS"] = macros

    setcover_dir = get_setcover_build_directory(out_dir)

    if not os.path.exists(setcover_dir):
        os.mkdir(setcover_dir)

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = setcover_dir

        if fuzz_target is None:
            raise RuntimeError(f"FUZZ_TARGET is not set")
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(setcover_dir, os.path.basename(fuzz_target))
    
    # dst = os.path.join(out_dir, 'setcover_' + os.path.basename(fuzz_target))

    # if os.path.exists(src):
    #     os.system(f"link {src} {dst}")
    #     return True 
    # else:
    #     return False
    
        try:
            utils.build_benchmark(env=new_env)

            for f in ["gen_graph.py", "setcover_sancov_cfg"]:
                tmp_path = os.path.join("/setcover", f)
                if os.path.exists(tmp_path):
                    shutil.copy(tmp_path, os.path.join(setcover_dir, f))

            
            graph_script = "/setcover/gen_graph.py"
            old_dir = os.getcwd()
            try:
                os.chdir(setcover_dir)
                final_fuzz_bin = new_env["FUZZ_TARGET"]
                subprocess.check_call(["python3", graph_script,
                                       final_fuzz_bin])
            finally:
                os.chdir(old_dir)
        except subprocess.CalledProcessError:
            print("[build_setcover_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            # if old_cflags is not None：
            #     os.environ["CFLAGS"] = old_cflags
            # if old_cxxflags is not None:
            #     os.environ["CXXFLAGS"] = old_cxxflags;
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    if (not is_build_failed) and fuzz_target:
        built_bin = os.path.join(setcover_dir, os.path.basename(fuzz_target))
        if os.path.exists(built_bin):
            shutil.copy(
                built_bin,
                os.path.join(out_dir, "setcover_" + os.path.basename(fuzz_target))
            )

    return (not is_build_failed)

# def build_libafl_binary():
#     print("[build_libafl_binary] Building libafl instrumentation.")
#     out_dir = os.getenv("OUT")
#     src = os.path.join(out_dir, "libafl_target_bin")
#     fuzz_target = os.getenv("FUZZ_TARGET")
#     dst = os.path.join(out_dir, 'libafl_' + os.path.basename(fuzz_target))

#     if os.path.exists(src):
#         os.system(f"link {src} {dst}")
#         return True 
#     else:
#         return False
    
def build_libafl_binary():
    print("[build_libafl_binary] Building libafl instrumentation.")
    is_build_failed = False

    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    fuzz_target = os.getenv("FUZZ_TARGET")
    out_dir = os.getenv("OUT")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")


    """Build benchmark."""
    os.environ['CC'] = ('/libafl/fuzzers/fuzzbench/fuzzbench'
                        '/target/release-fuzzbench/libafl_cc')
    os.environ['CXX'] = ('/libafl/fuzzers/fuzzbench/fuzzbench'
                         '/target/release-fuzzbench/libafl_cxx')

    os.environ['ASAN_OPTIONS'] = 'abort_on_error=0:allocator_may_return_null=1'
    os.environ['UBSAN_OPTIONS'] = 'abort_on_error=0'

    cflags = ['--libafl']
    cxxflags = ['--libafl', '--std=c++14']
    utils.append_flags('CFLAGS', cflags)
    utils.append_flags('CXXFLAGS', cxxflags)
    utils.append_flags('LDFLAGS', cflags)

    os.environ['FUZZER_LIB'] = '/stub_rt.a'

    libafl_dir = get_libafl_build_directory(out_dir)
    if not os.path.exists(libafl_dir):
        os.mkdir(libafl_dir)

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = libafl_dir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(libafl_dir, os.path.basename(fuzz_target))

        try:
            utils.build_benchmark(env=new_env)

        except subprocess.CalledProcessError:
            print("[build_libafl_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    if (not is_build_failed) and fuzz_target:
        built_bin = os.path.join(libafl_dir, os.path.basename(fuzz_target))
        if os.path.exists(built_bin):
            shutil.copy(built_bin, os.path.join(out_dir, "libafl_" + os.path.basename(fuzz_target)))

    return (not is_build_failed)

def build():
    """
    在 OSS-Fuzz 中被调用的主要构建入口。
    按顺序编译：fox、ztaint、vanilla、cmplog，
    并复制相应的 fuzzer 主程序到 /out。
    """
    install_all()
    prepare_build_environment()

    built_fox     = build_fox_binary()
    built_ztaint  = build_ztaint_binary()
    built_vanilla = build_vanilla_binary()
    built_cmplog  = build_cmplog_binary()
    built_setcover = build_setcover_binary()
    build_libafl = build_libafl_binary()


    # 复制 fuzzer 主程序。如果没编译成功, 也许不会用到, 但这里先都拷或者做检查
    if os.path.exists("/fox/afl-fuzz"):
        shutil.copy("/fox/afl-fuzz", os.path.join(os.environ["OUT"], "fox_4.30c_hybrid_start"))
    if os.path.exists("/ztaint/afl-fuzz"):
        shutil.copy("/ztaint/afl-fuzz", os.path.join(os.environ["OUT"], "ztaint_4.30c_hybrid_start"))
    if os.path.exists("/afl_vanilla/afl-fuzz"):
        shutil.copy("/afl_vanilla/afl-fuzz", os.path.join(os.environ["OUT"], "afl-fuzz-vanilla"))
        shutil.copy("/afl_vanilla/afl-fuzz", os.path.join(os.environ["OUT"], "cmplog_4.30c_hybrid_start"))
    # @yrd the fuzzer is compiled in $OUT. The fuzzer is $OUT/libafl_fuzzer.
    # if os.path.exists("/PATH/to/libafl-fuzzer"):
    #     shutil.copy("/path/to/libafl-fuzzer", os.path.join(os.environ["OUT"], "libafl_fuzzer"))
    """
    if os.path.exists("/setcover/main"):
        shutil.copy("/setcover/main", os.path.join(os.environ["OUT"], "setcover_4.30c_hybrid_start"))
    """
    # if os.path.exists("/setcover/gen_graph.py"):
    #     shutil.copy("/setcover/gen_graph.py", os.path.join(os.environ["OUT"], "gen_graph.py"))
    if os.path.exists("/setcover/afl-fuzz"):
        shutil.copy("/setcover/afl-fuzz", os.path.join(os.environ["OUT"], "setcover_fuzzer"))
        shutil.copy("/setcover/afl-fuzz", os.path.join(os.environ["OUT"], "setcover_4.30c_hybrid_start"))


    # ensemble_runner.py
    if os.path.exists("/ztaint/ensemble_runner.py"):
        shutil.copy("/ztaint/ensemble_runner.py", os.environ["OUT"])

    print("[build] Build results:")
    print("  FOX     :", "OK" if built_fox else "FAIL")
    print("  ZTaint  :", "OK" if built_ztaint else "FAIL")
    print("  Vanilla :", "OK" if built_vanilla else "FAIL")
    print("  CmpLog  :", "OK" if built_cmplog else "FAIL")
    print("  LibAFL  :", "OK" if build_libafl else "FAIL")
    print("  SetCover:", "OK" if built_setcover else "FAIL")

    if not any([built_fox, built_ztaint, built_vanilla, built_cmplog, build_libafl]):
        with open(os.path.join(os.getenv("OUT"), "is_vanilla"), "w") as f:
            f.write("all_failed")
        print("[build] All instrumentation failed.")


def prepare_fuzz_environment(input_corpus):
    """准备fuzz环境，比如设置AFL_NO_UI, AFL_AUTORESUME等。"""
    os.environ["AFL_NO_UI"] = "1"
    os.environ["AFL_SKIP_CPUFREQ"] = "1"
    os.environ["AFL_NO_AFFINITY"] = "1"
    os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    os.environ["AFL_SKIP_CRASHES"] = "1"
    os.environ["AFL_SHUFFLE_QUEUE"] = "1"
    os.environ["AFL_FAST_CAL"] = "1"
    os.environ["AFL_DISABLE_TRIM"] = "1"
    os.environ["AFL_CMPLOG_ONLY_NEW"] = "1"
    os.environ["AFL_AUTORESUME"] = "1"

    utils.create_seed_file_for_empty_corpus(input_corpus)

# def run_libafl_fuzz(input_corpus, output_corpus, target_binary):
#     out_dir = os.getenv("OUT")
#     target_binary = target_binary
#     subprocess.run(
#         f"{os.path.join(out_dir, target_binary)} --cores 1 --input {input_corpus} --output {output_corpus}",
#         shell=True
#     )

def run_afl_fuzz(input_corpus, output_corpus, target_binary, hide_output=False):
    """
    简单演示：判断是否存在 FOX / Ztaint / CmpLog 主程序，
    如果有就 ensemble_runner，否则回退 vanilla。
    """
    dictionary_path = utils.get_dictionary_path(target_binary)
    out_dir = os.getenv("OUT")

    van_bin = os.path.join(out_dir, "afl-fuzz-vanilla")

    fox_built_path = os.path.join(out_dir, "fox_" + os.path.basename(target_binary))
    ztaint_built_path = os.path.join(out_dir, "ztaint_" + os.path.basename(target_binary))
    cmplog_built_path = os.path.join(out_dir, "cmplog_" + os.path.basename(target_binary))
    libafl_build_path = os.path.join(out_dir, "libafl_" + os.path.basename(target_binary))
    setcover_build_path = os.path.join(out_dir, "setcover_" + os.path.basename(target_binary))

    has_any_ensemble = any([os.path.exists(fox_built_path),
                            os.path.exists(ztaint_built_path),
                            os.path.exists(cmplog_built_path),
                            os.path.exists(libafl_build_path),
                            os.path.exists(setcover_build_path)])
    if has_any_ensemble:
        cmd = [
            "python", "ensemble_runner.py",
            "-i", input_corpus, "-o", output_corpus,
            "-b", target_binary
        ]
        
        if os.path.exists(fox_built_path):
            cmd += ["--fox_target_binary", fox_built_path]
        
        if os.path.exists(ztaint_built_path):
            cmd += ["--ztaint_target_binary", ztaint_built_path]
        
        if os.path.exists(cmplog_built_path):
            cmd += ["--cmplog_target_binary", cmplog_built_path]
            

        if os.path.exists(libafl_build_path):
            cmd += ["--libafl_target_binary", libafl_build_path]
         

        if os.path.exists(setcover_build_path):
            cmd += ["--setcover_target_binary", setcover_build_path]

        if dictionary_path:
            cmd += ["-x", os.path.join("/out", "keyval.dict"), dictionary_path]

        print("[run_afl_fuzz] Ensemble command:", " ".join(cmd))
        output_stream = subprocess.DEVNULL if hide_output else None
        subprocess.check_call(cmd, stdout=output_stream, stderr=output_stream)
    else:
        if os.path.exists(van_bin):
            cmd = [
                van_bin,
                "-i", input_corpus,
                "-o", output_corpus,
                "-t", "1000+",
                "-m", "none",
                "--",
                target_binary
            ]
            if dictionary_path:
                cmd += ["-x", os.path.join("/out", "keyval.dict"), "-x", dictionary_path]

            print("[run_afl_fuzz] Vanilla command:", " ".join(cmd))
            output_stream = subprocess.DEVNULL if hide_output else None
            subprocess.check_call(cmd, stdout=output_stream, stderr=output_stream)
        else:
            print("[run_afl_fuzz] No valid fuzzer found, aborting.")


def fuzz(input_corpus, output_corpus, target_binary):
    """
    在 OSS-Fuzz 中实际执行fuzz的入口。
    """
    prepare_fuzz_environment(input_corpus)
    run_afl_fuzz(input_corpus, output_corpus, target_binary)