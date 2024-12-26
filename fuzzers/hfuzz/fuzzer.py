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

def get_cmplog_build_directory(target_directory):
    """Return path to CmpLog target directory."""
    return os.path.join(target_directory, "cmplog")

def get_vanilla_build_directory(target_directory):
    """Return path to vanilla target directory."""
    return os.path.join(target_directory, "vanilla")

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
        # 新增要求
        "pyelftools==0.30"
    ]
    for p in packages:
        install(p)

def prepare_build_environment():
    """
    对 benchmark 进行一些通用修复，如移除 -Wdocumentation/-Werror 等。
    不再在此处设定CC/CXX/FUZZER_LIB，
    因为 build_fox_binary、build_ztaint_binary、build_vanilla_binary、build_cmplog_binary
    会分别在内部设置。
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

def build_fox_binary():
    """Build FOX-instrumented binary (non-vanilla)."""
    print("[build_fox_binary] Building FOX instrumentation.")
    is_build_failed = False
    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    # 1) 切换编译器到 /fox
    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")

    os.environ["CC"] = "/fox/afl-clang-fast"
    os.environ["CXX"] = "/fox/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/fox/libAFLDriver.a"

    # 2) 输出字典信息
    os.environ["AFL_LLVM_DICT2FILE"] = os.path.join(os.environ["OUT"], "keyval.dict")
    os.environ["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"

    with utils.restore_directory(src), utils.restore_directory(work):
        try:
            # 编译
            utils.build_benchmark()

            # 拷贝中间信息 (instrument_meta_data 等)
            for f in ["br_src_map", "strcmp_err_log", "instrument_meta_data"]:
                path = os.path.join("/dev/shm", f)
                if os.path.exists(path):
                    shutil.copy(path, os.path.join(os.environ["OUT"], f))

            # 在执行 gen_graph_no_gllvm_15.py 前先 cd 到 $OUT
            fuzz_bin = os.path.join(os.environ["OUT"], os.environ["FUZZ_TARGET"])
            graph_script = "/fox/gen_graph_no_gllvm_15.py"
            out_dir = os.environ["OUT"]

            old_dir = os.getcwd()
            try:
                os.chdir(out_dir)
                subprocess.check_call(["python3", graph_script,
                                       fuzz_bin, "instrument_meta_data"])
            finally:
                os.chdir(old_dir)

        except subprocess.CalledProcessError:
            print("[build_fox_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            # 恢复环境变量
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    return (not is_build_failed)

def build_ztaint_binary():
    """Build ZTaint-instrumented binary."""
    print("[build_ztaint_binary] Building ZTaint instrumentation.")
    is_build_failed = False
    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    # 切换到 /ztaint
    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")
    os.environ["CC"] = "/ztaint/afl-clang-fast"
    os.environ["CXX"] = "/ztaint/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/ztaint/libAFLDriver.a"

    # 打开 dict2file
    os.environ["AFL_LLVM_DICT2FILE"] = os.path.join(os.environ["OUT"], "keyval.dict")
    os.environ["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"

    with utils.restore_directory(src), utils.restore_directory(work):
        try:
            utils.build_benchmark()

            # 拷贝中间信息
            for f in ["br_src_map", "strcmp_err_log", "instrument_meta_data"]:
                path = os.path.join("/dev/shm", f)
                if os.path.exists(path):
                    shutil.copy(path, os.path.join(os.environ["OUT"], f))

            # 同样切换到 $OUT 目录执行脚本
            fuzz_bin = os.path.join(os.environ["OUT"], os.environ["FUZZ_TARGET"])
            graph_script = "/fox/gen_graph_no_gllvm_15.py"
            out_dir = os.environ["OUT"]

            old_dir = os.getcwd()
            try:
                os.chdir(out_dir)
                subprocess.check_call([
                    "python3", graph_script,
                    fuzz_bin, "instrument_meta_data"
                ])
            finally:
                os.chdir(old_dir)

        except subprocess.CalledProcessError:
            print("[build_ztaint_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            # 恢复原有环境变量
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_lib is not None:
                os.environ["FUZZER_LIB"] = old_lib

    return (not is_build_failed)

def get_vanilla_build_directory(target_directory):
    return os.path.join(target_directory, "vanilla")

def build_vanilla_binary():
    """Build the vanilla AFL instrumented binary (no CmpLog)."""
    print("[build_vanilla_binary] Building vanilla instrumentation.")
    is_build_failed = False
    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")
    os.environ["CC"] = "/afl_vanilla/afl-clang-fast"
    os.environ["CXX"] = "/afl_vanilla/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/afl_vanilla/libAFLDriver.a"

    vanilla_outdir = get_vanilla_build_directory(os.getenv("OUT"))
    if not os.path.exists(vanilla_outdir):
        os.mkdir(vanilla_outdir)

    fuzz_target = os.getenv("FUZZ_TARGET")

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = vanilla_outdir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(vanilla_outdir,
                                                  os.path.basename(fuzz_target))
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

    # 如果成功，把产物复制回 OUT
    if not is_build_failed and fuzz_target:
        built_target = new_env["FUZZ_TARGET"]
        if os.path.exists(built_target):
            shutil.copy(built_target, os.path.join(os.getenv("OUT"), os.path.basename(fuzz_target)))

    return (not is_build_failed)

def build_cmplog_binary():
    """Build the cmplog binary under /afl_vanilla with AFL_LLVM_CMPLOG=1."""
    print("[build_cmplog_binary] Building cmplog instrumentation.")
    is_build_failed = False
    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_lib = os.environ.get("FUZZER_LIB")
    old_cmp = os.environ.get("AFL_LLVM_CMPLOG")

    os.environ["CC"] = "/afl_vanilla/afl-clang-fast"
    os.environ["CXX"] = "/afl_vanilla/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/afl_vanilla/libAFLDriver.a"
    os.environ["AFL_LLVM_CMPLOG"] = "1"

    cmplog_outdir = os.path.join(os.getenv("OUT"), "cmplog_build")
    if not os.path.exists(cmplog_outdir):
        os.mkdir(cmplog_outdir)

    fuzz_target = os.getenv("FUZZ_TARGET")

    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["OUT"] = cmplog_outdir
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(cmplog_outdir, os.path.basename(fuzz_target))

        try:
            utils.build_benchmark(env=new_env)
        except subprocess.CalledProcessError:
            print("[build_cmplog_binary] Failed, skip.")
            is_build_failed = True
        finally:
            os.chdir(pwd)
            # 恢复变量
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

    if not is_build_failed and fuzz_target:
        built_target = new_env["FUZZ_TARGET"]
        if os.path.exists(built_target):
            # 将其拷贝回 /out，并且改名为 cmplog_<target_binary>
            shutil.copy(built_target, os.path.join(os.getenv("OUT"), "cmplog_" + os.path.basename(fuzz_target)))

    return (not is_build_failed)

def build():
    """Build benchmark with fox, ztaint, afl_vanilla, cmplog."""
    install_all()
    prepare_build_environment()

    # 顺序编译
    built_fox = build_fox_binary()           # /fox
    built_ztaint = build_ztaint_binary()     # /ztaint
    built_vanilla = build_vanilla_binary()   # /afl_vanilla (no cmplog)
    built_cmplog = build_cmplog_binary()     # /afl_vanilla (with cmplog)

    # 拷贝对应的 fuzzer 主程序
    if os.path.exists("/fox/afl-fuzz"):
        shutil.copy("/fox/afl-fuzz", os.path.join(os.environ["OUT"], "fox_4.09c_hybrid_start"))
    if os.path.exists("/ztaint/afl-fuzz"):
        shutil.copy("/ztaint/afl-fuzz", os.path.join(os.environ["OUT"], "ztaint_4.09c_hybrid_start"))
    if os.path.exists("/afl_vanilla/afl-fuzz"):
        shutil.copy("/afl_vanilla/afl-fuzz", os.path.join(os.environ["OUT"], "afl-fuzz-vanilla"))
        # 同一个 /afl_vanilla/afl-fuzz 也可作为 cmplog 的可执行文件，但为了区分，这里也拷贝为 cmplog_4.09c_hybrid_start
        shutil.copy("/afl_vanilla/afl-fuzz", os.path.join(os.environ["OUT"], "cmplog_4.09c_hybrid_start"))

    # ensemble_runner 如果需要也可以复制
    if os.path.exists("/fox/ensemble_runner.py"):
        shutil.copy("/fox/ensemble_runner.py", os.environ["OUT"])

    print("[build] Build results:")
    print("    FOX     : {}".format("OK" if built_fox else "FAIL"))
    print("    ZTaint  : {}".format("OK" if built_ztaint else "FAIL"))
    print("    Vanilla : {}".format("OK" if built_vanilla else "FAIL"))
    print("    CmpLog  : {}".format("OK" if built_cmplog else "FAIL"))

    # 如果全部失败，根据需要写一个标记或者 raise
    if not (built_fox or built_ztaint or built_vanilla or built_cmplog):
        with open(os.path.join(os.getenv("OUT"), "is_vanilla"), "w") as f:
            f.write("all_failed")
        print("[build] All instrumentation failed - fallback or do something else.")


def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with AFL or another AFL-based fuzzer."""
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


def run_afl_fuzz(input_corpus, output_corpus, target_binary, hide_output=False):
    """
    简单示例：检查 fox_4.09c_hybrid_start、ztaint_4.09c_hybrid_start、cmplog_4.09c_hybrid_start 是否存在，
    如果存在，就调用 ensemble_runner，否则回退到 afl-fuzz-vanilla。
    """
    dictionary_path = utils.get_dictionary_path(target_binary)
    out_dir = os.getenv("OUT")

    fox_path = os.path.join(out_dir, "fox_4.09c_hybrid_start")
    ztaint_path = os.path.join(out_dir, "ztaint_4.09c_hybrid_start")
    cmplog_path = os.path.join(out_dir, "cmplog_4.09c_hybrid_start")
    vanilla_path = os.path.join(out_dir, "afl-fuzz-vanilla")

    # 是否有可以用于ensemble的binary
    has_ensemble = (os.path.exists(fox_path) or
                    os.path.exists(ztaint_path) or
                    os.path.exists(cmplog_path))

    if has_ensemble:
        command = [
            "python", "ensemble_runner.py",
            "-i", input_corpus, "-o", output_corpus,
            "-b", target_binary
        ]
        # 如果fox有，就加 --fox_target_binary
        if os.path.exists(fox_path):
            command += ["--fox_target_binary", target_binary]

        # 如果ztaint有，就加 --ztaint_target_binary
        if os.path.exists(ztaint_path):
            command += ["--ztaint_target_binary", target_binary]

        # 如果cmplog有，就加 --cmplog_target_binary
        # 假设 cmplog 编译产物在 /out/cmplog_<fuzz_target> (build_cmplog_binary 时拷贝的)
        cmplog_built = os.path.join(out_dir, "cmplog_" + os.path.basename(target_binary))
        if os.path.exists(cmplog_path) and os.path.exists(cmplog_built):
            command += ["--cmplog_target_binary", cmplog_built]

        if dictionary_path:
            command += ["-x", "/out/keyval.dict", dictionary_path]

        print("[run_afl_fuzz] Ensemble mode command:", " ".join(command))
        output_stream = subprocess.DEVNULL if hide_output else None
        subprocess.check_call(command, stdout=output_stream, stderr=output_stream)

    else:
        # 没有可用的 ensemble，就退回 vanilla
        if os.path.exists(vanilla_path):
            command = [
                vanilla_path,
                "-i", input_corpus,
                "-o", output_corpus,
                "-t", "1000+",
                "-m", "none",
                "--",
                target_binary
            ]
            if dictionary_path:
                # 如果有 keyval.dict，则先 -x /out/keyval.dict
                command += ["-x", "/out/keyval.dict", "-x", dictionary_path]

            print("[run_afl_fuzz] Vanilla mode command:", " ".join(command))
            output_stream = subprocess.DEVNULL if hide_output else None
            subprocess.check_call(command, stdout=output_stream, stderr=output_stream)
        else:
            print("[run_afl_fuzz] No valid fuzzer found. Aborting.")

def fuzz(input_corpus, output_corpus, target_binary):
    """执行具体的fuzz过程。"""
    prepare_fuzz_environment(input_corpus)
    run_afl_fuzz(input_corpus, output_corpus, target_binary)