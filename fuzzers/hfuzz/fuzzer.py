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
    """Check if the benchmark contains the string |name|"""
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
        "wcwidth==0.2.6"
    ]
    for p in packages:
        install(p)


def prepare_build_environment():
    """Set environment variables used to build targets for AFL-based fuzzers."""

    os.environ["CC"] = "/fox/afl-clang-fast"
    os.environ["CXX"] = "/fox/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/fox/libAFLDriver.a"

    # 针对特定 benchmark 的兼容处理
    if is_benchmark("mbedtls"):
        file_path = os.path.join(os.getenv("SRC"), "mbedtls",
                                 "library/CMakeLists.txt")
        if os.path.isfile(file_path):
            subst_cmd = r"sed -i 's/\(-Wdocumentation\)//g' " + file_path
            subprocess.check_call(subst_cmd, shell=True)

    if is_benchmark("openthread"):
        mbed_cmake_one = os.path.join(os.getenv("SRC"),
                                      "openthread/third_party/mbedtls/repo",
                                      "library/CMakeLists.txt")
        mbed_cmake_two = os.path.join(os.getenv("SRC"),
                                      "openthread/third_party/mbedtls/repo",
                                      "CMakeLists.txt")
        if os.path.isfile(mbed_cmake_one):
            subst_cmd = r"sed -i 's/\(-Wdocumentation\)//g' " + mbed_cmake_one
            subprocess.check_call(subst_cmd, shell=True)
        if os.path.isfile(mbed_cmake_two):
            subst_cmd = r"sed -i 's/\(-Werror\)//g' " + mbed_cmake_two
            subprocess.check_call(subst_cmd, shell=True)


def build_fox_binary():
    """Build FOX-instrumented binary (non-vanilla)."""
    is_vanilla = False
    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    print("[build fox] build target binary with FOX instrumentation")
    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    # 让 AFL_LLVM_DICT2FILE 把信息写入 keyval.dict
    os.environ["AFL_LLVM_DICT2FILE"] = os.path.join(os.environ["OUT"], "keyval.dict")
    os.environ["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"

    # 正常编译
    with utils.restore_directory(src), utils.restore_directory(work):
        try:
            utils.build_benchmark()

            # 拷贝编译后的中间件信息
            for f in ["br_src_map", "strcmp_err_log", "instrument_meta_data"]:
                src_file = os.path.join("/dev/shm", f)
                if os.path.exists(src_file):
                    shutil.copy(src_file, os.path.join(os.environ["OUT"], f))

            print("[build fox] generate metadata with gen_graph_no_gllvm_15.py")
            # 不再需要 get-bc / llvm-dis-15
            # 只需直接使用编译产物 fuzz_target 执行 graph 脚本
            env = os.environ.copy()
            fuzz_target = os.path.join(os.environ["OUT"], os.environ["FUZZ_TARGET"])

            gen_graph_python = "/fox/gen_graph_no_gllvm_15.py"
            subprocess.check_call([
                "python3", gen_graph_python,
                fuzz_target,
                "instrument_meta_data"
            ], env=env)

            os.chdir(pwd)
        except subprocess.CalledProcessError:
            print("[X] FOX instrumentation failed, fallback to vanilla.")
            os.chdir(pwd)
            is_vanilla = True
            return is_vanilla

    # 编译 FOX 对应的 cmplog 二进制
    is_vanilla = create_cmplog_binaries(afl_path="/fox_cmplog")
    return is_vanilla


def build_ztaint_binary():
    """Build ZTaint-instrumented binary (类似 fox)。"""
    is_vanilla = False
    subprocess.check_call(["rm", "-f", "/dev/shm/*"])

    print("[build ztaint] build target binary with ZTaint instrumentation")
    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    # 类似 fox，不再需要 gllvm
    # 先暂时保存 fox 下的 env，再替换成 ztaint 的 env
    old_cc = os.environ.get("CC")
    old_cxx = os.environ.get("CXX")
    old_fuzzer_lib = os.environ.get("FUZZER_LIB")

    os.environ["CC"] = "/ztaint/afl-clang-fast"
    os.environ["CXX"] = "/ztaint/afl-clang-fast++"
    os.environ["FUZZER_LIB"] = "/ztaint/libAFLDriver.a"

    # 同样让 AFL_LLVM_DICT2FILE 把信息写入 keyval.dict
    os.environ["AFL_LLVM_DICT2FILE"] = os.path.join(os.environ["OUT"], "keyval.dict")
    os.environ["AFL_LLVM_DICT2FILE_NO_MAIN"] = "1"

    with utils.restore_directory(src), utils.restore_directory(work):
        try:
            utils.build_benchmark()

            # 拷贝编译后的中间件信息
            for f in ["br_src_map", "strcmp_err_log", "instrument_meta_data"]:
                src_file = os.path.join("/dev/shm", f)
                if os.path.exists(src_file):
                    shutil.copy(src_file, os.path.join(os.environ["OUT"], f))

            print("[build ztaint] generate metadata with gen_graph_no_gllvm_15.py")
            env = os.environ.copy()
            fuzz_target = os.path.join(os.environ["OUT"], os.environ["FUZZ_TARGET"])

            gen_graph_python = "/fox/gen_graph_no_gllvm_15.py"
            subprocess.check_call([
                "python3", gen_graph_python,
                fuzz_target,
                "instrument_meta_data"
            ], env=env)

            os.chdir(pwd)
        except subprocess.CalledProcessError:
            print("[X] ZTaint instrumentation failed, fallback to vanilla.")
            os.chdir(pwd)
            # 恢复原先 env
            if old_cc is not None:
                os.environ["CC"] = old_cc
            if old_cxx is not None:
                os.environ["CXX"] = old_cxx
            if old_fuzzer_lib is not None:
                os.environ["FUZZER_LIB"] = old_fuzzer_lib

            is_vanilla = True
            return is_vanilla

    # 编译 ZTaint 对应的 cmplog 二进制
    is_vanilla = create_cmplog_binaries(afl_path="/ztaint_cmplog")
    # 恢复回 fox 的环境（因为后面还要用到 FOX 的二进制）
    if old_cc is not None:
        os.environ["CC"] = old_cc
    if old_cxx is not None:
        os.environ["CXX"] = old_cxx
    if old_fuzzer_lib is not None:
        os.environ["FUZZER_LIB"] = old_fuzzer_lib

    return is_vanilla


def create_cmplog_binaries(afl_path="/fox_cmplog"):
    """
    对指定的 afl_path（默认为 /fox_cmplog），构建使用 cmplog 模式的二进制。
    若失败则标记为 vanilla。
    """
    is_vanilla = False
    src = os.getenv("SRC")
    work = os.getenv("WORK")
    pwd = os.getcwd()

    # 主 cmplog 二进制
    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        cmplog_hybrid_dir_main = os.path.join(os.getenv("OUT"), "cmplog_hybrid_main")
        os.mkdir(cmplog_hybrid_dir_main)
        fuzz_target = os.getenv("FUZZ_TARGET")

        new_env["OUT"] = cmplog_hybrid_dir_main
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(cmplog_hybrid_dir_main,
                                                  os.path.basename(fuzz_target))

        new_env["CC"] = f"{afl_path}/afl-clang-fast"
        new_env["CXX"] = f"{afl_path}/afl-clang-fast++"
        new_env["FUZZER_LIB"] = f"{afl_path}/libAFLDriver.a"

        try:
            utils.build_benchmark(env=new_env)
            os.chdir(pwd)
        except subprocess.CalledProcessError:
            print("[X] Compilation or metadata gen failed for main cmplog")
            os.chdir(pwd)
            is_vanilla = True
            return is_vanilla

    # 支持性 cmplog 编译
    with utils.restore_directory(src), utils.restore_directory(work):
        new_env = os.environ.copy()
        new_env["AFL_LLVM_CMPLOG"] = "1"
        cmplog_hybrid_dir_support = os.path.join(os.getenv("OUT"), "cmplog_hybrid_support")
        os.mkdir(cmplog_hybrid_dir_support)
        fuzz_target = os.getenv("FUZZ_TARGET")

        new_env["OUT"] = cmplog_hybrid_dir_support
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(cmplog_hybrid_dir_support,
                                                  os.path.basename(fuzz_target))

        new_env["CC"] = f"{afl_path}/afl-clang-fast"
        new_env["CXX"] = f"{afl_path}/afl-clang-fast++"
        new_env["FUZZER_LIB"] = f"{afl_path}/libAFLDriver.a"

        try:
            utils.build_benchmark(env=new_env)
            os.chdir(pwd)
        except subprocess.CalledProcessError:
            print("[X] Compilation or metadata gen failed for support cmplog")
            os.chdir(pwd)
            is_vanilla = True
            return is_vanilla

    return is_vanilla


def build():
    """Build benchmark with FOX + ZTaint + (optional) fallback."""
    install_all()
    prepare_build_environment()

    is_fox_vanilla = build_fox_binary()     # 先构建 FOX
    is_ztaint_vanilla = build_ztaint_binary()  # 再构建 ZTaint

    # 若任一出现问题则回退 vanilla
    is_vanilla = (is_fox_vanilla or is_ztaint_vanilla)
    if is_vanilla:
        new_env = os.environ.copy()
        new_env["CC"] = "/afl_vanilla/afl-clang-fast"
        new_env["CXX"] = "/afl_vanilla/afl-clang-fast++"
        new_env["FUZZER_LIB"] = "/afl_vanilla/libAFLDriver.a"

        vanilla_build_directory = get_vanilla_build_directory(os.getenv("OUT"))
        os.mkdir(vanilla_build_directory)
        fuzz_target = os.getenv("FUZZ_TARGET")
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(vanilla_build_directory,
                                                  os.path.basename(fuzz_target))
        src = os.getenv("SRC")
        work = os.getenv("WORK")
        with utils.restore_directory(src), utils.restore_directory(work):
            utils.build_benchmark(env=new_env)

        # 将 vanilla 编译产物复制回到 /out
        shutil.copy(new_env["FUZZ_TARGET"], os.getenv("OUT"))

        # 接着构建 cmplog 版本
        new_env["AFL_LLVM_CMPLOG"] = "1"
        cmplog_build_directory = get_cmplog_build_directory(os.getenv("OUT"))
        os.mkdir(cmplog_build_directory)
        if fuzz_target:
            new_env["FUZZ_TARGET"] = os.path.join(cmplog_build_directory,
                                                  os.path.basename(fuzz_target))
        print("[vanilla build] Re-building benchmark for CmpLog fuzzing target")
        src = os.getenv("SRC")
        work = os.getenv("WORK")
        with utils.restore_directory(src), utils.restore_directory(work):
            utils.build_benchmark(env=new_env)

        # 写一个标志文件，表明回退到 vanilla
        with open(os.path.join(os.getenv("OUT"), "is_vanilla"), "w", encoding="utf-8") as f:
            f.write("is_vanilla")

    # 复制所需的 fuzzer 可执行文件
    print("[post_build] Copying afl-fuzz to $OUT directory")
    shutil.copy("/fox/afl-fuzz",
                os.path.join(os.environ["OUT"], "fox_4.09c_hybrid_start"))
    shutil.copy("/fox/ensemble_runner.py", os.environ["OUT"])
    shutil.copy("/fox_cmplog/afl-fuzz",
                os.path.join(os.environ["OUT"], "cmplog_4.09c_hybrid_start"))
    shutil.copy("/afl_vanilla/afl-fuzz",
                os.path.join(os.environ["OUT"], "afl-fuzz-vanilla"))

    # 如果需要同理复制 ztaint 的启动器
    # （假设 /ztaint/afl-fuzz 是编译好的 ztaint 主程序）
    if os.path.exists("/ztaint/afl-fuzz"):
        shutil.copy("/ztaint/afl-fuzz",
                    os.path.join(os.environ["OUT"], "ztaint_4.09c_hybrid_start"))


def prepare_fuzz_environment(input_corpus):
    """Prepare to fuzz with AFL or another AFL-based fuzzer."""
    os.environ["AFL_NO_UI"] = "1"
    os.environ["AFL_SKIP_CPUFREQ"] = "1"
    os.environ["AFL_NO_AFFINITY"] = "1"
    os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    os.environ["AFL_SKIP_CRASHES"] = "1"
    os.environ["AFL_SHUFFLE_QUEUE"] = "1"

    # 其他 AFL++ 优化参数
    os.environ["AFL_FAST_CAL"] = "1"
    os.environ["AFL_DISABLE_TRIM"] = "1"
    os.environ["AFL_CMPLOG_ONLY_NEW"] = "1"
    os.environ["AFL_AUTORESUME"] = "1"

    # 如果 corpus 是空，需要至少一个非空 seed
    utils.create_seed_file_for_empty_corpus(input_corpus)


def run_afl_fuzz(input_corpus, output_corpus, target_binary, hide_output=False):
    """Run afl-fuzz (ensemble_runner 或 vanilla)。"""
    is_vanilla = os.path.exists(os.path.join(os.getenv("OUT"), "is_vanilla"))
    dictionary_path = utils.get_dictionary_path(target_binary)

    print("[run_afl_fuzz] Running target with " + ("vanilla AFL" if is_vanilla else "ensemble (FOX + ZTaint + cmplog)"))
    if not is_vanilla:
        cmplog_main_dir = os.path.join(os.path.dirname(target_binary), "cmplog_hybrid_main")
        cmplog_main_bin = os.path.join(cmplog_main_dir, os.path.basename(target_binary))

        cmplog_supp_dir = os.path.join(os.path.dirname(target_binary), "cmplog_hybrid_support")
        cmplog_supp_bin = os.path.join(cmplog_supp_dir, os.path.basename(target_binary))

        # 这里假设 ensemble_runner.py 已修改，可以同时处理 fox + cmplog + ztaint
        command = [
            "python", "ensemble_runner.py",
            "-i", input_corpus, "-o", output_corpus,
            "-b", cmplog_main_bin,
            "--fox_target_binary", target_binary,    # FOX
            "--ztaint_target_binary", target_binary,  # ZTaint 这里示例，实际可另存一份
            "--cmplog_target_binary", cmplog_supp_bin,
            "-x", "/out/keyval.dict"
        ]
        if dictionary_path:
            command.append(dictionary_path)
    else:
        # vanilla 模式
        vanilla_bin = os.path.join(get_vanilla_build_directory(os.path.dirname(target_binary)),
                                   os.path.basename(target_binary))
        cmplog_bin = os.path.join(get_cmplog_build_directory(os.path.dirname(target_binary)),
                                  os.path.basename(target_binary))
        command = [
            "./afl-fuzz-vanilla",
            "-i", input_corpus,
            "-o", output_corpus,
            "-t", "1000+",
            "-m", "none",
            "-c", cmplog_bin,
            "-x", "/out/keyval.dict",
            "--",
            vanilla_bin
        ]
        if dictionary_path:
            command.extend(["-x", dictionary_path])

    print("[run_afl_fuzz] Running command:", " ".join(command))
    output_stream = subprocess.DEVNULL if hide_output else None
    subprocess.check_call(command, stdout=output_stream, stderr=output_stream)


def fuzz(input_corpus, output_corpus, target_binary):
    """Run afl-fuzz on target."""
    prepare_fuzz_environment(input_corpus)
    run_afl_fuzz(input_corpus, output_corpus, target_binary)