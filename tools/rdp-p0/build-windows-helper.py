"""Build the x64 Windows preview helper. Run via the guarded preview packaging script.
Requires Python 3.14 (tar.zst), MinGW-w64 UCRT gcc, CMake, Ninja and curl.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

VERSION = "3.32.2"
DEPS = {
    "libwinpthread-14.0.0.r598.ge3d18511f-1": "c35d6be83d141c8cfbb61f1637dd4b53aac8f5562d766aa26d0741c40bad4e4d",
    "openssl-3.6.5-1": "773e021ebad83f14b5c103db467411e8ff064663e1c7e7f730e2be72f4117064",
    "zlib-1.3.2-3": "130e6ef04c654fc2150a177600aa5ed0035087665a893479d2c85ba7485d5704",
    "cjson-1.7.19-1": "47dc4b9873657a4dfa35f0efe5746b172ee4ae622a12b93be00981a9c17911cd",
}
HERE = Path(__file__).resolve().parent


def unpack(work, name, url, digest, prefix):
    archive = work / name
    if not archive.exists():
        subprocess.run(["curl.exe", "-fLsS", "--retry", "2", "--max-time", "120",
                        url, "-o", str(archive)], check=True)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError(f"SHA-256 mismatch: {archive}")
    with tarfile.open(archive) as src:
        src.extractall(work, members=[m for m in src if m.name.startswith(prefix)], filter="data")


def build(work, out):
    work.mkdir(parents=True, exist_ok=True)
    source = work / f"freerdp-{VERSION}"
    unpack(work, "freerdp.tar.xz", f"https://pub.freerdp.com/releases/{source.name}.tar.xz",
           "8b9d2aaa976b8341ccc507408a3e89ef3ae8323e56bb3e520da2a0d963ff3b2f", source.name+"/")
    for package, digest in DEPS.items():
        name = f"mingw-w64-ucrt-x86_64-{package}-any.pkg.tar.zst"
        unpack(work, name, "https://repo.msys2.org/mingw/ucrt64/"+name, digest, "ucrt64/")
    obj, deps = work / "build", work / "ucrt64"
    channels = ("cliprdr", "drdynvc", "rdpgfx")
    off = ("WITH_CLIENT", "WITH_SERVER", "WITH_SERVER_INTERFACE", "WITH_SERVER_CHANNELS",
           "WITH_FFMPEG", "WITH_SWSCALE", "WITH_MANPAGES", "WITH_SAMPLE",
           "WITH_URIPARSER", "BUILD_TESTING", "WITH_CAIRO", "WITH_WEBVIEW", "WITH_FUSE",
           "WITH_CCACHE", "USE_UNWIND", "CMAKE_EXPORT_PACKAGE_REGISTRY", "CMAKE_INTERPROCEDURAL_OPTIMIZATION")
    subprocess.run(["cmake", "-S", source, "-B", obj, "-G", "Ninja",
                    f"-DCMAKE_PREFIX_PATH={deps.as_posix()}", f"-DOPENSSL_ROOT_DIR={deps.as_posix()}",
                    f"-DCMAKE_INSTALL_PREFIX={(work/'install').as_posix()}", "-DCMAKE_BUILD_TYPE=Release",
                    "-DCMAKE_C_FLAGS=-D__STDC_NO_THREADS__=1", "-DCMAKE_SHARED_LINKER_FLAGS=-static-libgcc",
                    "-DWITHOUT_FREERDP_3x_DEPRECATED=ON", "-DWITH_CLIENT_COMMON=ON",
                    "-DWITH_CHANNELS=ON", "-DWITH_CLIENT_CHANNELS=ON",
                    "-DWITH_MEDIA_FOUNDATION=ON",
                    *[f"-DCHANNEL_{p.parent.name.upper()}=OFF"
                      for p in (source/"channels").glob("*/ChannelOptions.cmake") if p.parent.name not in channels],
                    *[f"-DCHANNEL_{channel.upper()}{suffix}={value}" for channel in channels
                      for suffix, value in (("", "ON"), ("_CLIENT", "ON"), ("_SERVER", "OFF"))],
                    *[f"-D{x}=OFF" for x in off]], check=True)
    subprocess.run(["cmake", "--build", obj, "--target", "freerdp-client", "--parallel", "8"], check=True)
    out.mkdir(parents=True, exist_ok=True)
    exe = out / "calabi-rdp.exe"
    resource = work / "calabi-login.o"
    subprocess.run(["windres", "--codepage=65001", "-I", "../../apps/client-desktop/src-tauri/icons",
                    "windows_login.rc", "-O", "coff", "-o", str(resource)], cwd=HERE, check=True)
    receive_obj = work/"shell-receive.o"
    subprocess.run(["g++", "-std=c++17", "-O2", "-DCALABI_SHELL_RECEIVE", "-c",
                    HERE/"shell-paste-probe.cpp", "-o", receive_obj], check=True)
    receive_test = work/"shell-receive-test.exe"
    subprocess.run(["g++", "-std=c++17", "-O2", "-static", HERE/"windows_shell_receive_test.cpp",
                    "-o", receive_test, "-lole32", "-lshell32", "-luuid", "-luser32", "-lgdi32"], check=True)
    try:
        subprocess.run([receive_test], check=True, timeout=25)
    finally:
        receive_test.unlink(missing_ok=True)
    cflags = ["-std=gnu11", "-D__STDC_NO_THREADS__=1", "-D_WIN32_WINNT=0x0A00",
              "-DCALABI_SHELL_RECEIVE", "-DCALABI_REMOTE_WORKSPACE", "-DCALABI_RDP_GFX", "-DUNICODE", "-D_UNICODE", "-Wno-deprecated-declarations", "-O2",
              *["-I"+str(p/"include") for p in (source,obj,source/"winpr",obj/"winpr")]]
    objects = []
    for name in ("session", "clipboard", "windows_transport", "windows_window"):
        target = work/(name+".o")
        subprocess.run(["gcc", *cflags, "-c", HERE/(name+".c"), "-o", target], check=True)
        objects.append(target)
    subprocess.run(["g++", "-D__STDC_NO_THREADS__=1", "-D_WIN32_WINNT=0x0A00",
                    "-DUNICODE", "-D_UNICODE", "-Wno-deprecated-declarations", "-O2", "-municode",
                    "-mwindows", "-static-libgcc", "-static-libstdc++", "-s",
                    *["-I"+str(p/"include") for p in (source,obj,source/"winpr",obj/"winpr")],
                    *objects, receive_obj, resource,
                    "-L"+str(obj/"libfreerdp"), "-L"+str(obj/"winpr/libwinpr"), "-lfreerdp3", "-lwinpr3",
                    "-L"+str(obj/"client/common"), "-lfreerdp-client3",
                    "-lws2_32", "-liphlpapi", "-lcrypt32", "-lcredui", "-limm32", "-lgdi32", "-ldwmapi", "-lshell32", "-lole32", "-luuid", "-o", exe], check=True)
    for path in (obj/"libfreerdp/libfreerdp3.dll",obj/"winpr/libwinpr/libwinpr3.dll",
                 obj/"client/common/libfreerdp-client3.dll",
                 *[deps/"bin"/name for name in ("libssl-3-x64.dll","libcrypto-3-x64.dll","zlib1.dll","libcjson-1.dll","libwinpthread-1.dll")]):
        shutil.copy2(path,out/path.name)
    modules = out/"ossl-modules"
    modules.mkdir(exist_ok=True)
    shutil.copy2(deps/"lib/ossl-modules/legacy.dll", modules/"legacy.dll")
    licenses = out/"licenses"
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(source/"LICENSE", licenses/"FreeRDP.txt")
    for name in ("openssl","cjson","zlib"):
        shutil.copyfile(deps/"share/licenses"/name/"LICENSE", licenses/(name+".txt"))
    for path in (deps/"share/licenses").glob("*pthread*/*"):
        if path.is_file():
            shutil.copyfile(path, licenses/("winpthreads-"+path.name))
    # No developer PATH: a missing private DLL must fail at package time.
    env = dict(os.environ, PATH=str(Path(os.environ["SystemRoot"])/"System32"))
    gfx_test = work/"gfx-channel-test.exe"
    subprocess.run(["gcc", *cflags, "-static-libgcc", HERE/"gfx_channel_test.c",
                    "-L"+str(obj/"libfreerdp"), "-L"+str(obj/"winpr/libwinpr"),
                    "-L"+str(obj/"client/common"), "-lfreerdp-client3", "-lfreerdp3", "-lwinpr3",
                    "-o", gfx_test], check=True)
    try:
        subprocess.run([gfx_test, "--require-gfx"], check=True, cwd=out,
                       env=dict(env, PATH=str(out)+";"+env["PATH"]), timeout=20)
    finally:
        gfx_test.unlink(missing_ok=True)
    clipboard_test = work/"clipboard-test.exe"
    subprocess.run(["gcc", "-std=gnu11", "-D__STDC_NO_THREADS__=1", "-static-libgcc",
                    *["-I"+str(p/"include") for p in (source,obj,source/"winpr",obj/"winpr")],
                    HERE/"clipboard_test.c",
                    "-L"+str(obj/"libfreerdp"), "-L"+str(obj/"winpr/libwinpr"),
                    "-L"+str(obj/"client/common"), "-lfreerdp-client3", "-lfreerdp3", "-lwinpr3",
                    "-o", clipboard_test], check=True)
    try:
        subprocess.run([clipboard_test], check=True, cwd=out, env=dict(env, PATH=str(out)+";"+env["PATH"]))
    finally:
        clipboard_test.unlink(missing_ok=True)
    reverse_test = work/"reverse-channel-test.exe"
    subprocess.run(["gcc", "-std=gnu11", "-D__STDC_NO_THREADS__=1", "-static-libgcc", "-Wno-deprecated-declarations",
                    *["-I"+str(p/"include") for p in (source,obj,source/"winpr",obj/"winpr")],
                    HERE/"windows_shell_channel_test.c",
                    "-L"+str(obj/"libfreerdp"), "-L"+str(obj/"winpr/libwinpr"),
                    "-L"+str(obj/"client/common"), "-lfreerdp-client3", "-lfreerdp3", "-lwinpr3",
                    "-lole32", "-o", reverse_test], check=True)
    try:
        subprocess.run([reverse_test], check=True, cwd=out, env=dict(env, PATH=str(out)+";"+env["PATH"]), timeout=20)
    finally:
        reverse_test.unlink(missing_ok=True)
    native_test = work/"windows-clipboard-test.exe"
    subprocess.run(["gcc", "-std=gnu11", "-DUNICODE", "-D_UNICODE", "-static-libgcc",
                    HERE/"windows_clipboard_test.c", "-lshell32", "-lole32", "-o", native_test], check=True)
    try:
        subprocess.run([native_test],check=True,env=env,cwd=out)
    finally:
        native_test.unlink(missing_ok=True)
    login_test = work/"windows-login-test.exe"
    subprocess.run(["gcc", "-std=gnu11", "-DUNICODE", "-D_UNICODE", "-static-libgcc",
                    HERE/"windows_login_test.c", resource, "-lws2_32", "-lcrypt32", "-lcredui",
                    "-limm32", "-lgdi32", "-ldwmapi", "-lshell32", "-lole32", "-o", login_test],check=True)
    try:
        subprocess.run([login_test],check=True,env=env,cwd=out,timeout=20)
    finally:
        login_test.unlink(missing_ok=True)
    presentation_test = work/"presentation-test.exe"
    subprocess.run(["gcc", *[flag for flag in cflags if flag not in {"-DCALABI_SHELL_RECEIVE", "-DCALABI_RDP_GFX"}],
                    HERE/"windows_presentation_test.c",
                    "-L"+str(obj/"libfreerdp"), "-L"+str(obj/"winpr/libwinpr"),
                    "-lfreerdp3", "-lwinpr3", "-lws2_32", "-o", presentation_test], check=True)
    try:
        subprocess.run([presentation_test], check=True, cwd=out,
                       env=dict(env, PATH=str(out)+";"+env["PATH"]), timeout=20)
    finally:
        presentation_test.unlink(missing_ok=True)
    subprocess.run([exe,"--self-test"],check=True,env=env,cwd=out)
    paste = out/"calabi-paste.exe"
    paste_resource = work/"calabi-paste-version.o"
    subprocess.run(["windres", "-D", "CALABI_PASTE", "-I", "../../apps/client-desktop/src-tauri/icons", "windows_helper_version.rc",
                    "-O", "coff", "-o", str(paste_resource)], cwd=HERE, check=True)
    subprocess.run(["g++", "-std=c++17", "-O2", "-static", "-municode", "-mwindows",
                    HERE/"shell-paste-probe.cpp", paste_resource, "-o", paste,
                    "-lole32", "-lshell32", "-lshlwapi", "-ladvapi32", "-luuid", "-luser32", "-lgdi32"],check=True)
    subprocess.run([paste,"--self-test"],check=True,env=env,cwd=out,timeout=20)
    subprocess.run([paste,"--progress-ui-test"],check=True,env=env,cwd=out,timeout=20)
    menu_test = work/"remote-menu-test.exe"
    subprocess.run(["g++", "-std=c++17", "-O2", "-static", HERE/"windows_remote_menu_test.cpp",
                    "-o", menu_test, "-lole32", "-lshell32", "-lshlwapi", "-ladvapi32", "-luuid", "-luser32", "-lgdi32"],check=True)
    try:
        subprocess.run([menu_test,paste],check=True,env=env,cwd=out,timeout=30)
    finally:
        menu_test.unlink(missing_ok=True)
    forward_test = work/"forward-rdp-test.exe"
    subprocess.run(["g++", "-std=c++17", "-O2", "-static", HERE/"shell_rdp_forward_test.cpp",
                    "-o", forward_test, "-lole32", "-lshell32", "-lshlwapi", "-ladvapi32", "-luuid", "-luser32", "-lgdi32"],check=True)
    try:
        subprocess.run([forward_test],check=True,env=env,cwd=out,timeout=25)
    finally:
        forward_test.unlink(missing_ok=True)
    pin = hashlib.sha256(bytes([1,2,3])).hexdigest()
    mesh_test = work/"mesh-copy-test.exe"
    subprocess.run(["g++", "-std=c++17", "-O2", "-static", HERE/"shell_mesh_copy_test.cpp",
                    "-o", mesh_test, "-lole32", "-lshell32", "-lshlwapi", "-ladvapi32", "-luuid", "-luser32", "-lgdi32"],check=True)
    try:
        subprocess.run([mesh_test],check=True,env=env,cwd=out,timeout=20)
    finally:
        mesh_test.unlink(missing_ok=True)
    for answer, success in ((pin,True), ("0"*64,False)):
        r = subprocess.run([exe,"--check-pin"],env=env,cwd=out,text=True,input=answer+"\n",capture_output=True)
        if (r.returncode==0)!=success or r.stdout.strip().lower()!="rdp-pin "+pin:
            raise RuntimeError("RDP certificate verification check failed")


if __name__=="__main__":
    out=Path(sys.argv[1]).resolve()
    if os.environ.get("CALABI_RDP_SDK_WORK"):
        build(Path(os.environ["CALABI_RDP_SDK_WORK"]).resolve(),out)
    else:
        with tempfile.TemporaryDirectory(prefix="calabi-rdp-build-") as temp:
            build(Path(temp),out)
