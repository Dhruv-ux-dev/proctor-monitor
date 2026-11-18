"""
proctor_monitor.py  -  test-session monitor for Windows and macOS (consent-based proctoring)

Install:
  Windows:  pip install psutil pynput
  macOS:    pip3 install psutil pynput        (pynput also installs the pyobjc Quartz bindings)

Run:
  python proctor_monitor.py --session CANDIDATE_ID --token PER_SESSION_SECRET --server https://host/api/heartbeat

Testing aids:
  --selftest          start fake "cheat" helpers (network tool on a VNC port, hidden overlay
                      window, injected key presses) and check that each one is detected
  --find TEXT         show everything the monitor sees about programs matching TEXT
  --debug-net         list every non-system program with network sockets + signature status

macOS permissions (System Settings > Privacy & Security), granted to Terminal / your Python:
  - Input Monitoring + Accessibility   needed for the injected-input check
  - Run with sudo to see root daemons' sockets/paths (optional; works without it)

What it checks (rename-proof: identity comes from signatures/metadata, not file names):
  1. Baseline of running programs before the test; new programs that use the network
  2. Program identity: Windows file metadata + Authenticode signer,
     macOS bundle id + code-signing identity/Team ID
  3. Unsigned / ad-hoc-signed / broken-signature programs (custom tools)
  4. Known remote-access tools and floating interview-assistant apps (Cluely, Parakeet AI, ...)
  5. Remote session (RDP, Quick Assist, macOS Screen Sharing / ARD), inbound remote ports
  6. Injected keyboard/mouse input (remote-control tools must inject input)
  7. Windows hidden from screen capture + see-through always-on-top overlays
  8. Virtual machines: test run inside a VM, or a VM / Hyper-V / WSL2 / Sandbox running next to it
  9. Extra monitors, sustained upload (screen streaming)
 10. Signed heartbeat (HMAC) with sequence numbers so gaps/forgeries are visible server-side

The script only REPORTS. The server makes the decision and a human reviews flagged sessions.
Anything that runs on the candidate's own machine can be modified by the candidate, so treat a
clean report as "nothing obvious found", never as proof of honesty.
"""

import argparse
import ctypes
import hashlib
import hmac
import json
import os
import plistlib
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import psutil

# fix 1
import platform
import statistics

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

# ----------------------------- CONFIG ---------------------------------
SERVER_URL = os.environ.get("PROCTOR_SERVER", "")       # "" = log locally only
SESSION_ID = os.environ.get("PROCTOR_SESSION", "CANDIDATE_ID")
SESSION_TOKEN = os.environ.get("PROCTOR_TOKEN", "")     # per-session secret from the server, signs heartbeats
INTERVAL = 5               # seconds between checks
LOG_FILE = "proctor_log.jsonl"
EXPECTED_MONITORS = 1
# Identity keywords, matched as whole words against metadata / signer / bundle id (not just the filename)
REMOTE_IDENTITY_HINTS = [
    "anydesk", "teamviewer", "rustdesk", "ultraviewer", "parsec", "splashtop",
    "chrome remote desktop", "remoting_host", "chromoting", "remote_desktop", "realvnc", "tightvnc",
    "ultravnc", "tigervnc", "supremo", "ammyy", "aeroadmin", "dwservice", "meshcentral", "meshagent",
    "connectwise", "screenconnect", "logmein", "gotoassist", "remote utilities", "radmin",
    "nomachine", "zoho assist", "dameware", "bomgar", "beyondtrust", "remotepc", "hoptodesk",
    "getscreen", "litemanager", "iperius remote", "take control", "pulseway", "atera", "action1",
    "x2go", "rdpwrap", "rdp wrapper", "kaseya", "n-able", "sunlogin", "todesk", "anyviewer",
    "mikogo", "showmypc", "join.me", "windows remote assistance", "quick assist", "jump desktop",
    "screens 5", "deskreen",
]
# Tools sold specifically for cheating in coding interviews/tests (mostly invisible overlays)
CHEAT_TOOL_HINTS = [
    "cluely", "interview coder", "interviewcoder", "interview-coder", "leetcode wizard",
    "leetcodewizard", "final round ai", "finalround", "lockedin ai", "lockedinai",
    "parakeet ai", "parakeetai", "interview solver", "interviewsolver",
]
# Extra text matched against window titles only (the browser shows the active tab's title)
CHEAT_SITE_HINTS = ["cluely.com", "interviewcoder.co", "leetcodewizard.io", "finalroundai.com",
                    "lockedinai.com", "parakeet-ai.com", "interviewsolver.com"]
# Long, unambiguous brand names: also match with a suffix (RemotePCSuite, RemotePCService, AnyDeskHelper)
PREFIX_HINTS = {"remotepc", "anydesk", "teamviewer", "rustdesk", "ultraviewer", "hoptodesk", "cluely"}
# Ports commonly used by remote-access tools (checked outbound, inbound and listening)
REMOTE_PORTS = {5938, 7070, 6568, 5900, 5901, 5500, 3389, 3283, 4899,
                21115, 21116, 21117, 21118, 21119}

# Programs that run arbitrary scripts: identity = exe + command line
INTERPRETERS = {"python", "pythonw", "py", "node", "java", "javaw", "powershell", "pwsh",
                "wscript", "cscript", "cmd", "ruby", "perl", "php", "dotnet", "mshta",
                "bash", "sh", "zsh", "deno", "bun", "osascript"}

# OS components that are remote-session servers. They live in system folders, so they are
# checked by name: if one of them has a live connection, someone is viewing/controlling the screen.
REMOTE_SESSION_PROCS = {"msra.exe", "quickassist.exe", "screensharingd", "ardagent"}

# macOS Mac-to-Mac screen sharing parts. launchd starts every one of them on demand only, so a
# running one means a sharing session is active (or just ended). Covers Screen Sharing / ARD
# (screensharingd, ScreensharingAgent), Messages / Apple ID sharing relayed through Apple's servers
# that never touches port 5900 (AppleVNCServer, SSInvitationAgent), the "your screen is being
# shared" menu-bar item (SSMenuAgent), and the viewer app used to watch another Mac.
MAC_SHARING_PROCS = {"screensharingd", "screensharingagent", "applevncserver", "ssinvitationagent",
                     "ssmenuagent", "screen sharing"}

# Processes that ARE a running virtual machine on the host. Matched by name because several live
# in system folders (Hyper-V's vmwp.exe) or have no readable path (vmmem, vmmemWSL).
VM_PROCESS_NAMES = {
    # Hyper-V / WSL2 / Windows Sandbox / Docker (Hyper-V or WSL2 backend)
    "vmwp", "vmmem", "vmmemwsl", "windowssandbox", "windowssandboxclient", "windowssandboxremotesession",
    # VirtualBox, VMware, QEMU, Parallels, UTM, Apple Virtualization framework, Docker Desktop (mac)
    "virtualboxvm", "vboxheadless", "vmware-vmx", "vmware-vmx-debug", "vmware-vmx-stats",
    "qemulauncher", "prl_vm_app", "prl_client_app", "com.apple.virtualization.virtualmachine",
    "com.docker.virtualization", "com.docker.krun", "com.docker.hyperkit", "vfkit",
}
VM_PROCESS_PREFIXES = ("qemu-system-",)

# Helper programs that only exist INSIDE a VM (guest tools). Seeing one = this script runs in a VM.
VM_GUEST_PROCS = {"vmtoolsd", "vm3dservice", "vmwaretray", "vmwareuser", "vmware-tools-daemon",
                  "vboxservice", "vboxtray", "vboxclient", "prl_tools", "prl_tools_service", "prl_cc",
                  "qemu-ga", "spice-vdagent", "spice-vdagentd", "xenservice"}

# Windows features that let a VM run. True = the pre-check refuses to start until they are turned off
# (student needs a reboot; it also disables WSL2 / Docker / Windows Sandbox on that machine).
# False = only report them to the server.
BLOCK_HYPERV_FEATURE = True
HYPERV_FEATURES = ("Microsoft-Hyper-V-Hypervisor", "VirtualMachinePlatform", "Containers-DisposableClientVM",
                   "HypervisorPlatform")

OVERLAY_SCAN_SEC = 1.0     # fast background scan for capture-hidden windows (cheap: a few ms per scan)

UPLOAD_ALERT_BPS = 150 * 1024     # bytes/sec
UPLOAD_STREAK_NEEDED = 3          # consecutive checks above the limit

# Folders full of unsigned developer-tool binaries; the "unsigned program (no network)" check skips them.
# Trade-off: a tool hidden inside one of these folders is skipped too. Paths are lowercase with "/".
IGNORE_PATH_PARTS = ("/.vscode/extensions/", "/node_modules/", "/site-packages/", "/.cargo/",
                     "/.rustup/", "/.nuget/", "/.gradle/", "/.m2/",
                     "/opt/homebrew/", "/usr/local/cellar/", "/library/developer/",
                     # Conda / pyenv Pythons are ad-hoc signed on Apple Silicon (tested: /opt/anaconda3/bin/python3.14)
                     "/anaconda3/", "/miniconda3/", "/miniforge3/", "/mambaforge/", "/.conda/", "/.pyenv/")

USER_DIR_PARTS = ("/users/", "/temp/", "/tmp/", "/downloads/", "/private/var/folders/")

WEIGHTS = {
    "cheat_tool": 80,            # known interview-cheating app
    "cheat_site": 60,            # window title (usually a browser tab) names a cheating tool/site
    "remote_identity": 60,       # metadata / signature matches a remote-access tool
    "remote_port": 25,
    "new_proc_network": 20,
    "userpath_network": 15,
    "remote_session": 70,
    "extra_monitor": 25,
    "injected_input": 40,
    "vm_strong": 30,
    "vm_weak": 5,
    "heartbeat_failed": 5,
    "unsigned_network": 40,      # unsigned / ad-hoc / broken-signature program using the network
    "unsigned_program": 30,      # same, no network
    "unreadable_processes": 0,   # info only
    "hidden_overlay": 50,        # window hidden from screen capture/sharing
    "transparent_overlay": 25,   # see-through, always-on-top window
    "script_network": 35,        # new interpreter/script talking to the network
    "sustained_upload": 30,      # steady high upload, typical of screen streaming
    "vm_running": 60,            # a VM / WSL2 / Sandbox / Docker VM is running next to the test
    "sharing_enabled": 50,       # macOS Screen Sharing / Remote Management switched on (anyone can connect)
    "overlay_check_blind": 30,   # macOS: no Screen Recording permission, hidden-overlay check cannot run
}

PRECHECK_BLOCKERS = ("vm_running", "cheat_tool", "cheat_site", "remote_identity", "remote_port", "remote_session",
                     "sharing_enabled", "overlay_check_blind", "extra_monitor", "script_network", "unsigned_network",
                     "unsigned_program", "hidden_overlay")


# ---------------------------- HELPERS ---------------------------------
def norm(path):
    """Lowercase, forward slashes: one form for matching on both OSes."""
    return (path or "").replace("\\", "/").lower()


def _hint_rx(hints):
    """Whole word, except brands in PREFIX_HINTS, which also match with a suffix (RemotePCSuite)."""
    return [(h, re.compile(r"(?<![a-z0-9])" + re.escape(h) + ("" if h in PREFIX_HINTS else r"(?![a-z0-9])")))
            for h in hints]


_REMOTE_RX, _CHEAT_RX = _hint_rx(REMOTE_IDENTITY_HINTS), _hint_rx(CHEAT_TOOL_HINTS)
_SITE_RX = _hint_rx(CHEAT_TOOL_HINTS + CHEAT_SITE_HINTS)


def match_hint(text, compiled):
    """Whole-word match, so 'atera' does not fire on 'collateral'."""
    for h, rx in compiled:
        if rx.search(text):
            return h
    return None


def interp_name(exe_l):
    base = exe_l.rsplit("/", 1)[-1]
    if base.endswith(".exe"):
        base = base[:-4]
    base = re.sub(r"[\d.\-]+$", "", base)          # python3.12 -> python, node18 -> node
    return base if base in INTERPRETERS else None


def vm_proc(name):
    n = (name or "").lower()
    if n.endswith(".exe"):
        n = n[:-4]
    return n if (n in VM_PROCESS_NAMES or n.startswith(VM_PROCESS_PREFIXES)) else None


def guest_proc_signals():
    hits = set()
    for p in psutil.process_iter(["name"]):
        n = (p.info.get("name") or "").lower()
        n = n[:-4] if n.endswith(".exe") else n
        if n in VM_GUEST_PROCS:
            hits.add("guest_tools:" + n)
    return sorted(hits)

# fix 2
TIMING_SLOW_TICKS = 1000   # CPUID on real hardware is ~100-300 ticks; a VM exit costs 1000s

_CODE_TIME_CPUID = bytes.fromhex("53" "0F31" "48C1E220" "4809D0" "4989C0" "31C0" "0FA2"
                                 "0F31" "48C1E220" "4809D0" "4C29C0" "5B" "C3")
_CODE_HV_BIT = bytes.fromhex("53" "B801000000" "31C9" "0FA2" "89C8" "5B" "C3")


def _make_exec_func(code):
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
    addr = k32.VirtualAlloc(None, len(code), 0x3000, 0x40)
    if not addr:
        raise OSError("VirtualAlloc failed")
    ctypes.memmove(addr, code, len(code))
    return ctypes.CFUNCTYPE(ctypes.c_uint64)(addr)


def cpuid_signals():
    """(strong, weak). Windows, 64-bit x86 only. Any problem -> ([], []), so it never breaks the script.
    Hypervisor bit True + slow CPUID = weak (a normal PC with VBS / Hyper-V looks like this).
    Hypervisor bit False + slow CPUID = strong (the bit is being hidden, or something is wrong)."""
    try:
        if not IS_WIN or platform.machine().lower() not in ("amd64", "x86_64") \
                or ctypes.sizeof(ctypes.c_void_p) != 8:
            return [], []
        timing = _make_exec_func(_CODE_TIME_CPUID)
        hv_bit = bool(_make_exec_func(_CODE_HV_BIT)() & (1 << 31))
        for _ in range(100):
            timing()
        med = int(statistics.median([timing() for _ in range(500)]))
        if med <= TIMING_SLOW_TICKS:
            return [], []
        if hv_bit:
            return [], ["cpuid_slow:%d" % med]
        return ["cpuid_hidden_hypervisor:%d" % med], []
    except Exception:
        return [], []
# 
    
def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace",
                           creationflags=0x08000000 if IS_WIN else 0)   # CREATE_NO_WINDOW
        return (r.stdout or "") + (r.stderr or ""), r.returncode
    except Exception:
        return "", None


def chunks(seq, n):
    seq = list(seq)
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


_identity_cache = {}     # norm(path) -> lowercase identity text
_sig_cache = {}          # norm(path) -> valid | notsigned | adhoc | invalid | unknown


# ============================== WINDOWS ================================
def pe_signed(path):
    """True/False if the exe has an embedded Authenticode blob (PE header read, no PowerShell).
    None if unreadable / not a PE file. Presence only: it can be faked and it misses
    catalog-signed files, so suspicious results are confirmed with Get-AuthenticodeSignature."""
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return None
            f.seek(0x3C)
            pe = int.from_bytes(f.read(4), "little")
            f.seek(pe)
            hdr = f.read(264)
        if hdr[:4] != b"PE\0\0":
            return None
        magic = int.from_bytes(hdr[24:26], "little")              # 0x10B = PE32, 0x20B = PE32+
        cert_entry = 24 + (96 if magic == 0x10B else 112) + 4 * 8  # data directory #4 = certificates
        size = int.from_bytes(hdr[cert_entry + 4:cert_entry + 8], "little")
        return size > 0
    except Exception:
        return None


def ps(cmd, timeout=10):
    out, _ = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                  "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd], timeout=timeout)
    return out.strip()


def ps_indexed(paths, body, timeout=60):
    """Run `body` for each path in ONE PowerShell call. body sees $p and $i and prints "$i`t...".
    Results are keyed by index, so path spelling/case never breaks the mapping."""
    arr = ",".join("'%s'" % p.replace("'", "''") for p in paths)
    script = ("$a=@(" + arr + "); for($i=0;$i -lt $a.Length;$i++){ $p=$a[$i]; "
              "try { " + body + " } catch { \"$i`terror\" } }")
    res = {}
    for line in ps(script, timeout=timeout).splitlines():
        idx, _, rest = line.partition("\t")
        if idx.strip().isdigit():
            res[int(idx)] = rest
    return res


WIN_VERSIONINFO = ('$v=(Get-Item -LiteralPath $p).VersionInfo; '
                   '"$i`t$($v.OriginalFilename)|$($v.CompanyName)|$($v.ProductName)|$($v.FileDescription)"')
WIN_AUTHENTICODE = ('$s=Get-AuthenticodeSignature -LiteralPath $p; '
                    '"$i`t$($s.Status)`t$($s.SignerCertificate.Subject)"')

VM_STRINGS = ["vmware", "virtualbox", "vbox", "qemu", "kvm", "xen", "parallels", "bochs",
              "virtual machine"]
VM_MAC_PREFIXES = ("00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "08:00:27", "00:1c:42", "00:15:5d")
HYPERV_MAC = "00:15:5d"   # also on the host's "vEthernet (...)" adapters when WSL2/Docker/Hyper-V is installed


def vm_from_text(text):
    t = text.lower()
    return sorted({"string:" + s for s in VM_STRINGS
                   if re.search(r"(?<![a-z0-9])" + re.escape(s) + r"(?![a-z0-9])", t)})


def mac_addr_signals(default_iface):
    """VM MAC prefix on the adapter that carries the default route = strong. On any other adapter
    (VMware/VirtualBox host-only adapters on a real machine) = weak."""
    strong, weak = [], []
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family != psutil.AF_LINK:
                continue
            mac = (a.address or "").lower().replace("-", ":")
            if mac.startswith(VM_MAC_PREFIXES):
                on_route = bool(default_iface) and ifname == default_iface
                if mac.startswith(HYPERV_MAC) and ifname.lower().startswith("vethernet"):
                    on_route = False          # host side of a Hyper-V switch, not a guest
                (strong if on_route else weak).append(
                    "mac:%s@%s" % (mac[:8], ifname))
    return strong, weak


AFFINITY_NAMES = {0x01: "WDA_MONITOR", 0x11: "WDA_EXCLUDEFROMCAPTURE"}


class WinPlatform:
    name = "windows"
    system_prefixes = ("c:/windows/",)

    def __init__(self):
        self.user32 = ctypes.windll.user32
        self._confirmed = set()
        self._u32_ready = False

    def prefetch(self, paths, sock_paths):
        paths = sorted(set(paths))
        todo = [p for p in paths if norm(p) not in _identity_cache]
        for chunk in chunks(todo, 60):
            res = ps_indexed(chunk, WIN_VERSIONINFO)
            for i, p in enumerate(chunk):
                _identity_cache[norm(p)] = (os.path.basename(p) + " " + res.get(i, "")).lower()
        for p in paths:
            k = norm(p)
            if k not in _sig_cache:
                s = pe_signed(p)
                _sig_cache[k] = "unknown" if s is None else ("valid" if s else "notsigned")
        # Confirm with Authenticode: anything that looks unsigned (could be catalog-signed = fine)
        # and every program with sockets (embedded blob could be fake/self-signed).
        socks = {norm(p) for p in sock_paths}
        confirm = [p for p in paths if norm(p) not in self._confirmed
                   and (_sig_cache[norm(p)] == "notsigned" or norm(p) in socks)]
        for chunk in chunks(confirm, 30):
            res = ps_indexed(chunk, WIN_AUTHENTICODE, timeout=90)
            for i, p in enumerate(chunk):
                k = norm(p)
                self._confirmed.add(k)
                if i not in res:
                    continue
                status, _, subject = res[i].partition("\t")
                st = status.strip().lower()
                if st in ("valid", "notsigned"):
                    _sig_cache[k] = st
                elif st and st not in ("notsupportedfileformat", "error", "unknownerror"):
                    _sig_cache[k] = "invalid"          # HashMismatch, NotTrusted, ...
                if subject.strip():
                    _identity_cache[k] = _identity_cache.get(k, "") + " " + subject.strip().lower()

    def remote_session(self, est):
        return bool(self.user32.GetSystemMetrics(0x1000))      # SM_REMOTESESSION

    def sharing_flags(self, procs):
        return []

    def monitors(self):
        return self.user32.GetSystemMetrics(80)                   # SM_CMONITORS

    def vm_signals(self):
        out = ps("Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,HypervisorPresent | Format-List")
        out += ps("Get-CimInstance Win32_BIOS | Select Manufacturer,SerialNumber,Version | Format-List")
        out += ps("Get-CimInstance Win32_VideoController | Select Name | Format-List")
        out += ps("Get-CimInstance Win32_BaseBoard | Select Manufacturer,Product | Format-List")
        strong = vm_from_text(out) + guest_proc_signals()
        # the disk Windows booted from: "VMware Virtual disk", "VBOX HARDDISK", "QEMU HARDDISK",
        # "Msft Virtual Disk" (Hyper-V guest). Other mounted virtual disks on a real PC are ignored.
        boot = ps("$i=(Get-CimInstance Win32_DiskPartition | Where-Object BootPartition | Select -First 1).DiskIndex; "
                  "(Get-CimInstance Win32_DiskDrive | Where-Object Index -eq $i).Model").lower()

        # change 5 (fix the guest detection only dependent on the network card’s address (MAC) and the word “virtual machine”)
        # if any(k in boot for k in ("vmware", "vbox", "qemu", "virtual disk", "parallels", "xen")):
            #
        if any(k in boot for k in ("vmware", "vbox", "qemu", "virtual disk", "virtual hd", "parallels", "xen")):
            strong.append("boot_disk:" + boot.strip()[:40])
            
        # change 6
        # Hyper-V guest-only signals: the key is absent on the host, and the heartbeat service
        # exists on hosts too (Stopped), so only "running" counts
        try:
            import winreg
            winreg.CloseKey(winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                           r"SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"))
            strong.append("hyperv_guest_key")
        except Exception:
            pass
        try:
            if psutil.win_service_get("vmicheartbeat").status() == "running":
                strong.append("hyperv_heartbeat_running")
        except Exception:
            pass

        # HypervisorPresent is also true on real Windows 11 laptops with VBS / Memory Integrity: weak only
        weak = ["hypervisor_flag"] if "hypervisorpresent : true" in out.lower() else []
        feats = ps("Get-CimInstance Win32_OptionalFeature -Filter 'InstallState=1' | Where-Object { $_.Name -in @("
                   + ",".join("'%s'" % f for f in HYPERV_FEATURES) + ") } | ForEach-Object { $_.Name }",
                   timeout=40)
        weak += ["feature:" + f.strip() for f in feats.splitlines() if f.strip()]
        # fallback if the feature query is blocked: the Hyper-V management service exists only when Hyper-V is on
        if ps("Get-Service vmms -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }").strip().lower() == "vmms":
            weak.append("feature:Microsoft-Hyper-V (vmms service)")
        iface = ps("(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
                   "Sort-Object RouteMetric | Select -First 1).InterfaceAlias") or None
        s2, w2 = mac_addr_signals(iface)

        # fix 3
        # return sorted(set(strong + s2)), sorted(set(weak + w2))
        s3, w3 = cpuid_signals()
        return sorted(set(strong + s2 + s3)), sorted(set(weak + w2 + w3))

    def _setup_u32(self):
        import ctypes.wintypes as wt
        if self._u32_ready:
            return
        u = self.user32
        self.EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
        u.IsWindowVisible.argtypes = [wt.HWND]
        u.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        u.GetWindowDisplayAffinity.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        u.GetWindowLongW.argtypes = [wt.HWND, ctypes.c_int]
        u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        u.EnumWindows.argtypes = [self.EnumWindowsProc, wt.LPARAM]
        self._u32_ready = True

    def overlays(self):
        """(kind, pid, title, detail) for other programs' top-level windows that are
          - hidden from screen capture: SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE / WDA_MONITOR),
            the flag Cluely-style overlays set. Checked on EVERY window, visible or not, because these
            tools hide/show the overlay with a hotkey and the flag stays on while it is hidden.
          - see-through + always-on-top + click-through (visible windows only)."""
        import ctypes.wintypes as wt
        self._setup_u32()
        u = self.user32
        WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_EX_LAYERED = 0x8, 0x20, 0x80000
        me, found = os.getpid(), []

        def cb(hwnd, _lp):
            try:
                visible = bool(u.IsWindowVisible(hwnd))
                pid = wt.DWORD()
                u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value in (0, me):
                    return True
                aff = wt.DWORD(0)
                u.GetWindowDisplayAffinity(hwnd, ctypes.byref(aff))
                ex = u.GetWindowLongW(hwnd, -20)                   # GWL_EXSTYLE
                kind = None
                if aff.value != 0:
                    kind = "hidden_overlay"
                elif visible and (ex & WS_EX_TOPMOST) and (ex & WS_EX_LAYERED) and (ex & WS_EX_TRANSPARENT):
                    kind = "transparent_overlay"
                if kind:
                    buf = ctypes.create_unicode_buffer(256)
                    u.GetWindowTextW(hwnd, buf, 256)
                    found.append((kind, pid.value, buf.value,
                                  {"affinity": AFFINITY_NAMES.get(aff.value, aff.value), "visible": visible}))
            except Exception:
                pass
            return True

        u.EnumWindows(self.EnumWindowsProc(cb), 0)
        return found

    def window_titles(self):
        """(pid, title) for visible top-level windows."""
        import ctypes.wintypes as wt
        self._setup_u32()
        u = self.user32
        found = []

        def cb(hwnd, _lp):
            try:
                if u.IsWindowVisible(hwnd):
                    pid = wt.DWORD()
                    u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                    buf = ctypes.create_unicode_buffer(256)
                    u.GetWindowTextW(hwnd, buf, 256)
                    if buf.value:
                        found.append((pid.value, buf.value))
            except Exception:
                pass
            return True

        u.EnumWindows(self.EnumWindowsProc(cb), 0)
        return found

    def input_listener_kwargs(self, count):
        def kb(msg, data):
            count(bool(data.flags & 0x12), None)     # LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED
            return True

        def ms(msg, data):
            count(bool(data.flags & 0x03), None)     # LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED
            return True
        return {"win32_event_filter": kb}, {"win32_event_filter": ms}

    def input_permission(self):
        return True, ""


# =============================== macOS =================================
def parse_codesign(text):
    """Parse `codesign -dv --verbose=2` output into a status + identity fields."""
    if not text.strip() or "no such file" in text.lower():
        return {"status": "unknown"}
    if "not signed at all" in text:
        return {"status": "notsigned"}

    def field(k):
        m = re.search(r"^%s=(.*)$" % k, text, re.M)
        return m.group(1).strip() if m else ""

    info = {"identifier": field("Identifier"), "team": field("TeamIdentifier"),
            "authorities": re.findall(r"^Authority=(.*)$", text, re.M)}
    if field("Signature") == "adhoc" or "adhoc" in field("CodeDirectory").lower():
        info["status"] = "adhoc"         # Apple Silicon auto-signs every self-built binary this way
    elif "Software Signing" in info["authorities"]:
        info["status"] = "valid"         # Apple's own binaries (TeamIdentifier "not set")
    elif info["team"] and info["team"] != "not set":
        info["status"] = "team"          # Developer ID signed: still needs --verify
    else:
        info["status"] = "unknown"
    return info


def mac_bundle_ident(path):
    """Info.plist of the outermost and innermost .app containing `path` (renaming the .app or
    the binary does not change CFBundleIdentifier)."""
    out = []
    idxs = [m.start() for m in re.finditer(r"\.app/Contents/", path)]
    for i in sorted({idxs[0], idxs[-1]}) if idxs else []:
        try:
            with open(path[:i + 4] + "/Contents/Info.plist", "rb") as f:
                d = plistlib.load(f)
            out += [str(d.get(k, "")) for k in ("CFBundleIdentifier", "CFBundleName",
                                                 "CFBundleDisplayName", "CFBundleExecutable")]
        except Exception:
            pass
    return " ".join(x for x in out if x)


def parse_netstat_inbound(text, ports):
    """macOS `netstat -an -p tcp`: established connections whose LOCAL port is a remote-access port
    and whose peer is not loopback. Works without root (unlike per-pid socket lists)."""
    hits = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith("tcp") or parts[5] != "ESTABLISHED":
            continue
        local, remote = parts[3], parts[4]
        lport = local.rsplit(".", 1)[-1]
        rip = remote.rsplit(".", 1)[0]
        if lport.isdigit() and int(lport) in ports and not is_loopback(rip):
            hits.add(int(lport))
    return sorted(hits)


def mac_sharing_from(launchctl_rc, disabled_text, proc_names):
    """Which macOS sharing services are switched on. Inputs are raw command output so this can be
    tested without changing the Mac's settings.
      Screen Sharing: launchd loads com.apple.screensharing (disabled by default) only when it is on.
      Remote Management: ARDAgent runs only while it is on (it also turns Screen Sharing on)."""
    on = []
    if launchctl_rc == 0 or re.search(r'"com\.apple\.screensharing"\s*=>\s*(enabled|false)', disabled_text):
        on.append("Screen Sharing")
    if "ardagent" in proc_names:
        on.append("Remote Management")
    return on


def mac_vm_from(hv_vmm, model, features):
    strong = []
    if hv_vmm.strip() == "1":
        strong.append("kern.hv_vmm_present")
    m = model.strip().lower()                      # e.g. "VirtualMac2,1" (Apple VMs/UTM), "VMware7,1"
    strong += ["model:" + m for s in ("virtual", "vmware", "parallels", "vbox", "qemu") if s in m][:1]
    if re.search(r"(?<![A-Z0-9])VMM(?![A-Z0-9])", features):
        strong.append("cpu:VMM")
    return strong


class MacPlatform:
    name = "macos"
    system_prefixes = ("/system/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/",
                       "/library/apple/")

    def __init__(self):
        self._cg = None
        self.overlay_blind = False
        self._ws_pids = {p.pid for p in psutil.process_iter(["name"]) if p.info["name"] == "WindowServer"}

    def _one(self, path):
        text, _ = run(["codesign", "-dv", "--verbose=2", path])
        info = parse_codesign(text)
        status = info["status"]
        if status == "team":
            _, rc = run(["codesign", "--verify", path], timeout=30)
            status = "valid" if rc == 0 else ("invalid" if rc is not None else "unknown")
        ident = " ".join([os.path.basename(path), info.get("identifier", ""), info.get("team", ""),
                          " ".join(info.get("authorities", [])), mac_bundle_ident(path)]).lower()
        return status, ident

    def prefetch(self, paths, sock_paths):
        todo = sorted({p for p in paths if norm(p) not in _sig_cache})
        if not todo:
            return
        with ThreadPoolExecutor(8) as ex:
            for p, (status, ident) in zip(todo, ex.map(self._one, todo)):
                _sig_cache[norm(p)] = status
                _identity_cache[norm(p)] = ident

    def remote_session(self, est):
        out, _ = run(["netstat", "-an", "-p", "tcp"])
        return bool(parse_netstat_inbound(out, {5900, 3283}))   # Screen Sharing / ARD in use

    def sharing_flags(self, procs):
        """Mac-to-Mac screen sharing on any transport. Needs no root: launchctl output and process
        names are readable by a normal user."""
        flags = []
        for pid, p in procs.items():                    # active session, including Messages / Apple ID
            if p["name"].lower() in MAC_SHARING_PROCS:
                flags.append({"type": "remote_session", "proc": p["name"], "exe": p["exe"] or p["name"],
                              "pid": pid, "via": "macos_screen_sharing"})
        _, rc = run(["launchctl", "print", "system/com.apple.screensharing"])
        disabled, _ = run(["launchctl", "print-disabled", "system"])
        names = {p["name"].lower() for p in procs.values()}
        for svc in mac_sharing_from(rc, disabled, names):
            flags.append({"type": "sharing_enabled", "service": svc})
        return flags

    def _coregraphics(self):
        if self._cg is None:
            import ctypes.util
            path = ctypes.util.find_library("CoreGraphics") or \
                "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
            self._cg = ctypes.cdll.LoadLibrary(path)
        return self._cg

    def monitors(self):
        try:
            n = ctypes.c_uint32(0)
            self._coregraphics().CGGetActiveDisplayList(0, None, ctypes.byref(n))
            return int(n.value)
        except Exception:
            return -1

    def vm_signals(self):
        hv, _ = run(["sysctl", "-n", "kern.hv_vmm_present"])
        model, _ = run(["sysctl", "-n", "hw.model"])
        feats, _ = run(["sysctl", "-n", "machdep.cpu.features"])
        strong = mac_vm_from(hv, model, feats) + guest_proc_signals()
        route, _ = run(["route", "-n", "get", "default"])
        m = re.search(r"interface:\s*(\S+)", route)
        s2, w2 = mac_addr_signals(m.group(1) if m else None)
        return sorted(set(strong + s2)), sorted(set(w2))

    def _windows(self, all_windows=False):
        import Quartz
        opts = Quartz.kCGWindowListOptionAll if all_windows else \
            Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements
        return Quartz.CGWindowListCopyWindowInfo(opts, Quartz.kCGNullWindowID) or []

    def overlays(self):
        """kCGWindowSharingState 0 = window excluded from screen capture (NSWindowSharingNone),
        the trick invisible interview-helper overlays use. Checked on EVERY window, on screen or not:
        tools like Cluely hide the overlay with a hotkey and the flag stays on while it is hidden
        (tested: Cluely's hidden overlay drops out of the on-screen list but stays in the full one).
        See-through floating windows are checked on on-screen windows only."""
        me, found = os.getpid(), []
        try:
            import Quartz
            # Without Screen Recording permission macOS reports sharing state 0 for most other apps'
            # windows (tested: Chrome, WhatsApp, VS Code, Finder, Dock...), so the result would be
            # noise. Report the check as blind instead (see overlay_blind / "overlay_check_blind").
            self.overlay_blind = hasattr(Quartz, "CGPreflightScreenCaptureAccess") and \
                not Quartz.CGPreflightScreenCaptureAccess()
            if self.overlay_blind:
                return found
            wins = self._windows(all_windows=True)
        except Exception:
            return found
        for w in wins:
            try:
                pid = int(w.get("kCGWindowOwnerPID", 0))
                if pid in (0, me):
                    continue
                sharing = int(w.get("kCGWindowSharingState", 1))
                layer = int(w.get("kCGWindowLayer", 0))
                alpha = float(w.get("kCGWindowAlpha", 1.0))
                b = w.get("kCGWindowBounds") or {}
                big = float(b.get("Width", 0)) >= 80 and float(b.get("Height", 0)) >= 40
                title = str(w.get("kCGWindowName") or w.get("kCGWindowOwnerName") or "")
                onscreen = bool(w.get("kCGWindowIsOnscreen"))
                kind = None
                if sharing == 0 and big:
                    kind = "hidden_overlay"
                elif onscreen and layer > 0 and alpha < 0.95 and big:
                    kind = "transparent_overlay"
                if kind:
                    found.append((kind, pid, title, {"sharing": sharing, "layer": layer,
                                                     "alpha": round(alpha, 2), "visible": onscreen}))
            except Exception:
                continue
        return found

    def window_titles(self):
        """(pid, title) for on-screen windows. Titles of other apps need Screen Recording permission."""
        try:
            return [(int(w.get("kCGWindowOwnerPID", 0)), str(w.get("kCGWindowName")))
                    for w in self._windows() if w.get("kCGWindowName")]
        except Exception:
            return []

    def input_listener_kwargs(self, count):
        import Quartz
        field = getattr(Quartz, "kCGEventSourceUnixProcessID", 41)
        ignore = {0} | self._ws_pids

        def intercept(event_type, event):
            try:
                src = int(Quartz.CGEventGetIntegerValueField(event, field))
            except Exception:
                src = 0
            count(src not in ignore, src)        # hardware events carry no source process
            return event                          # never swallow the event
        return {"darwin_intercept": intercept}, {"darwin_intercept": intercept}

    def input_permission(self):
        missing = []
        try:
            import Quartz
            if hasattr(Quartz, "CGPreflightListenEventAccess") and not Quartz.CGPreflightListenEventAccess():
                missing.append("Input Monitoring")
                if hasattr(Quartz, "CGRequestListenEventAccess"):
                    Quartz.CGRequestListenEventAccess()
            if hasattr(Quartz, "CGPreflightScreenCaptureAccess") and not Quartz.CGPreflightScreenCaptureAccess():
                missing.append("Screen Recording")      # without it, window titles (site check) are empty
        except Exception:
            missing.append("Input Monitoring (pyobjc Quartz not installed)")
        try:
            from ApplicationServices import AXIsProcessTrusted
            if not AXIsProcessTrusted():
                missing.append("Accessibility")
        except Exception:
            pass
        if not missing:
            return True, ""
        return False, ("Grant " + " and ".join(missing) + " to this Terminal/Python in System Settings > "
                       "Privacy & Security, then restart the monitor.")


# ====================== GENERIC (Linux: tests only) ======================
class GenericPlatform:
    name = "generic"
    system_prefixes = ("/usr/", "/bin/", "/sbin/", "/lib/")

    def prefetch(self, paths, sock_paths):
        for p in paths:
            _identity_cache.setdefault(norm(p), os.path.basename(p).lower())
            _sig_cache.setdefault(norm(p), "unknown")

    def remote_session(self, est):
        return False

    def sharing_flags(self, procs):
        return []

    def monitors(self):
        return -1

    def vm_signals(self):
        return guest_proc_signals(), []

    def overlays(self):
        return []

    def window_titles(self):
        return []

    def input_listener_kwargs(self, count):
        return None, None

    def input_permission(self):
        return True, ""


PLAT = WinPlatform() if IS_WIN else MacPlatform() if IS_MAC else GenericPlatform()


def is_system(exe_l):
    return exe_l.startswith(PLAT.system_prefixes)


# --------------------- INJECTED INPUT DETECTION -----------------------
injected_count = 0
real_count = 0
injected_by = {}          # macOS only: source pid -> events
_lock = threading.Lock()


def _count(injected, src):
    global injected_count, real_count
    with _lock:
        if injected:
            injected_count += 1
            if src:
                injected_by[src] = injected_by.get(src, 0) + 1
        else:
            real_count += 1


def start_input_listeners():
    try:
        from pynput import keyboard, mouse
    except Exception:
        print("pynput not available - injected input check disabled")
        return False
    kb_kw, ms_kw = PLAT.input_listener_kwargs(_count)
    if kb_kw is None:
        return False
    keyboard.Listener(on_press=lambda k: None, **kb_kw).start()
    mouse.Listener(on_click=lambda *a: None, on_move=lambda *a: None, **ms_kw).start()
    return True


# ------------------------ FAST OVERLAY WATCHER --------------------------
# Overlays are often shown for only a few seconds. This thread scans windows every OVERLAY_SCAN_SEC
# and remembers every hit (with the program name, resolved immediately in case it exits) until the
# next heartbeat collects it.
_ov_lock = threading.Lock()
_ov_seen = {}


def resolve_proc(pid):
    try:
        pr = psutil.Process(pid)
        name = pr.name()
    except Exception:
        return "?", ""
    try:
        exe = pr.exe() or ""
    except Exception:
        exe = ""                      # e.g. elevated program while the monitor is not admin
    return name, exe


def overlay_watch():
    while True:
        try:
            hits = PLAT.overlays()
        except Exception:
            hits = []
        now = time.time()
        for kind, pid, title, detail in hits:
            key = (kind, pid, title)
            with _ov_lock:
                if key in _ov_seen:
                    _ov_seen[key]["last_seen"] = now
                    continue
            name, exe = resolve_proc(pid)
            with _ov_lock:
                _ov_seen[key] = dict(detail, proc=name, exe=exe, first_seen=now, last_seen=now)
        time.sleep(OVERLAY_SCAN_SEC)


def take_overlays():
    with _ov_lock:
        items = list(_ov_seen.items())
        _ov_seen.clear()
    return items


# ------------------------------ CHECKS ---------------------------------
def list_procs():
    procs = {}
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        exe = p.info.get("exe") or ""
        procs[p.info["pid"]] = {"pid": p.info["pid"], "name": p.info.get("name") or "",
                                "exe": exe, "exe_l": norm(exe), "cmdline": p.info.get("cmdline") or []}
    return procs


def proc_key(p):
    """Normal apps: exe path. Interpreters: exe + command line ("python a.py" != "python b.py")."""
    if interp_name(p["exe_l"]):
        return p["exe_l"] + "|" + " ".join(p["cmdline"]).lower()
    return p["exe_l"]


def snapshot_keys(procs=None):
    return {proc_key(p) for p in (procs or list_procs()).values() if p["exe"]}


def collect_net(pids):
    """established: pid -> [(local_port, remote_ip, remote_port)] (non-loopback peers only)
       listening:   pid -> [port] (non-loopback binds)"""
    est, lis = {}, {}

    def add(pid, c):
        if c.status == psutil.CONN_ESTABLISHED and c.raddr and not is_loopback(c.raddr.ip):
            est.setdefault(pid, []).append((c.laddr.port if c.laddr else 0, c.raddr.ip, c.raddr.port))
        elif c.status == psutil.CONN_LISTEN and c.laddr and not is_loopback(c.laddr.ip):
            lis.setdefault(pid, []).append(c.laddr.port)

    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid:
                add(c.pid, c)
        return est, lis
    except (psutil.AccessDenied, PermissionError):
        pass
    # macOS without root: system-wide listing is denied, but each of the user's own processes can be asked
    for pid in pids:
        try:
            p = psutil.Process(pid)
            conns = p.net_connections(kind="inet") if hasattr(p, "net_connections") else p.connections(kind="inet")
        except Exception:
            continue
        for c in conns:
            add(pid, c)
    return est, lis


def run_checks(baseline, procs=None):
    procs = procs or list_procs()
    est, lis = collect_net(list(procs))
    flags = []
    me = os.getpid()

    paths, sock_paths = set(), set()
    for pid, p in procs.items():
        if p["exe"] and not is_system(p["exe_l"]):
            paths.add(p["exe"])
            if pid in est or pid in lis:
                sock_paths.add(p["exe"])
    PLAT.prefetch(paths, sock_paths)

    for pid, p in procs.items():
        if pid != me and vm_proc(p["name"]):          # before the path check: vmmem has no readable path
            flags.append({"type": "vm_running", "proc": p["name"], "exe": p["exe"] or p["name"],
                          "pid": pid, "vm": vm_proc(p["name"])})
        if pid == me or not p["exe"]:
            continue
        exe, exe_l, name = p["exe"], p["exe_l"], p["name"]
        conns, listen = est.get(pid, []), sorted(set(lis.get(pid, [])))
        is_new = proc_key(p) not in baseline
        system = is_system(exe_l)
        base = {"proc": name, "exe": exe, "pid": pid}

        if not system:
            sig = _sig_cache.get(exe_l, "unknown")
            if sig in ("notsigned", "adhoc", "invalid"):
                if conns or listen:
                    flags.append(dict(base, type="unsigned_network", signature=sig, listening=listen))
                elif not any(part in exe_l for part in IGNORE_PATH_PARTS):
                    flags.append(dict(base, type="unsigned_program", signature=sig))
            ident = _identity_cache.get(exe_l, os.path.basename(exe_l))
            for kind, rx in (("cheat_tool", _CHEAT_RX), ("remote_identity", _REMOTE_RX)):
                hit = match_hint(ident, rx)
                if hit:
                    flags.append(dict(base, type=kind, match=hit))
                    break

        if interp_name(exe_l) and conns and is_new:
            flags.append(dict(base, type="script_network", cmd=" ".join(p["cmdline"])[:200]))

        # remote-access ports: outbound to one, inbound on one we listen on, or (non-system) listening
        out_p = {rp for _, _, rp in conns if rp in REMOTE_PORTS}

        ## change4
        # inbound detction on port 5000 failure fix -> 
        # in_p = {lp for lp, _, _ in conns if lp in REMOTE_PORTS and lp in listen}
        in_p = {lp for lp, _, _ in conns if lp in REMOTE_PORTS}

        lis_p = set() if system else {lp for lp in listen if lp in REMOTE_PORTS}
        if out_p or in_p or lis_p:
            flags.append(dict(base, type="remote_port", outbound=sorted(out_p),
                              inbound=sorted(in_p), listening=sorted(lis_p)))

        if is_new and conns:
            flags.append(dict(base, type="new_proc_network"))
            if not system and any(part in exe_l for part in USER_DIR_PARTS):
                flags.append(dict(base, type="userpath_network"))

        if name.lower() in REMOTE_SESSION_PROCS and conns:
            flags.append(dict(base, type="remote_session"))

    if PLAT.remote_session(est):
        flags.append({"type": "remote_session"})
    flags += PLAT.sharing_flags(procs)

    unreadable = sorted({p["name"] for pid, p in procs.items() if not p["exe"] and pid > 4})
    if unreadable:
        flags.append({"type": "unreadable_processes", "names": unreadable[:40]})

    overlay_hits = {}
    for kind, opid, title, detail in PLAT.overlays():
        op = procs.get(opid)
        name, exe = (op["name"], op["exe"]) if op else resolve_proc(opid)
        overlay_hits[(kind, opid, title)] = dict(detail, proc=name, exe=exe)
    for key, info in take_overlays():                  # hits from the 1-second watcher since last check
        overlay_hits.setdefault(key, info)
    if getattr(PLAT, "overlay_blind", False):
        flags.append({"type": "overlay_check_blind"})
    for (kind, opid, title), info in overlay_hits.items():
        if info["exe"] and is_system(norm(info["exe"])):
            continue                                   # unreadable path is NOT skipped: still reported
        flags.append(dict(info, type=kind, pid=opid, title=title[:80]))

    for tpid, title in PLAT.window_titles():           # only matching titles are ever reported
        hit = match_hint(title.lower(), _SITE_RX)
        if hit and tpid != me:
            tp = procs.get(tpid)
            name, exe = (tp["name"], tp["exe"]) if tp else resolve_proc(tpid)
            flags.append({"type": "cheat_site", "proc": name, "exe": exe, "pid": tpid,
                          "match": hit, "title": title[:80]})

    monitors = PLAT.monitors()
    if monitors > EXPECTED_MONITORS:
        flags.append({"type": "extra_monitor", "count": monitors})

    return flags, monitors


def score_of(flags, injected_delta, vm_strong, vm_weak, hb_failed):
    seen, score = set(), 0
    for f in flags:
        key = (f["type"], f.get("exe", ""))
        if key in seen:
            continue
        seen.add(key)
        score += WEIGHTS.get(f["type"], 10)
    if injected_delta >= 3:
        score += WEIGHTS["injected_input"]
    if vm_strong:
        score += WEIGHTS["vm_strong"]
    if vm_weak:
        score += WEIGHTS["vm_weak"]
    if hb_failed:
        score += WEIGHTS["heartbeat_failed"]
    return score


def level(score):
    return "HIGH" if score >= 80 else "MEDIUM" if score >= 40 else "LOW" if score >= 15 else "OK"


def own_hash():
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""


def send(payload):
    """Append to the local log and POST (HMAC-signed when a session token is set)."""
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    with open(LOG_FILE, "a", encoding="utf-8") as fh:
        fh.write(body.decode() + "\n")
    if not SERVER_URL:
        return True
    headers = {"Content-Type": "application/json"}
    if SESSION_TOKEN:
        headers["X-Proctor-Signature"] = hmac.new(SESSION_TOKEN.encode(), body, hashlib.sha256).hexdigest()
    try:
        req = urllib.request.Request(SERVER_URL, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=4) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


# --------------------------- TESTING AIDS ------------------------------
def debug_net():
    procs = list_procs()
    est, lis = collect_net(list(procs))
    rows = [p for pid, p in procs.items() if p["exe"] and not is_system(p["exe_l"])
            and (pid in est or pid in lis)]
    PLAT.prefetch([p["exe"] for p in rows], [p["exe"] for p in rows])
    print("Programs with network sockets (outside system folders):\n")
    for p in rows:
        pid = p["pid"]
        print(f"{p['name']:<26} pid={pid:<6} sig={_sig_cache.get(p['exe_l'], '?'):<10} "
              f"out={len(est.get(pid, []))} listen={sorted(set(lis.get(pid, [])))}")
        print(f"    {p['exe']}  {' '.join(p['cmdline'])[:110]}")
        print(f"    identity: {_identity_cache.get(p['exe_l'], '')[:150]}")
    if not rows:
        print("(none found)")


def find_proc(text):
    text = text.lower()
    procs = list_procs()
    est, lis = collect_net(list(procs))
    hits = [p for p in procs.values()
            if text and text in " ".join([p["name"], p["exe"], " ".join(p["cmdline"])]).lower()]
    if not hits:
        print(f"No running program matches '{text}'.")
        return
    PLAT.prefetch([p["exe"] for p in hits if p["exe"]], [])
    for p in hits:
        pid = p["pid"]
        print(f"pid={pid}  name={p['name']}")
        print(f"    exe = {p['exe'] or 'NOT READABLE (run as Administrator / sudo)'}")
        print(f"    cmd = {' '.join(p['cmdline'])[:150]}")
        print(f"    sig = {_sig_cache.get(p['exe_l'], 'n/a')}   out={len(est.get(pid, []))}   "
              f"listen={sorted(set(lis.get(pid, [])))}   system={is_system(p['exe_l'])}")
        print(f"    identity = {_identity_cache.get(p['exe_l'], '')[:150]}")


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))          # no packet is sent
        ip = s.getsockname()[0]
        s.close()
        if not is_loopback(ip):
            return ip
    except Exception:
        pass
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and not is_loopback(a.address):
                return a.address
    return None


HELPER_NET = r"""
import socket, sys, time
ip = sys.argv[1]
for port in (5900, 5901, 5500):
    try:
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port)); s.listen(1); break
    except OSError:
        s.close(); port = None
c = socket.create_connection((ip, port)); a, _ = s.accept()
print(port, flush=True)
time.sleep(40)
"""

HELPER_OVERLAY_WIN = r"""
import tkinter as tk, ctypes
r = tk.Tk(); r.title("proctor-selftest-overlay"); r.geometry("300x200+60+60"); r.attributes("-topmost", True)
r.update()
h = int(r.wm_frame(), 16)
if not ctypes.windll.user32.SetWindowDisplayAffinity(h, 0x11):   # WDA_EXCLUDEFROMCAPTURE
    ctypes.windll.user32.SetWindowDisplayAffinity(h, 0x01)       # WDA_MONITOR (older Windows)
r.after(40000, r.destroy); r.mainloop()
"""

HELPER_OVERLAY_MAC = r"""
from AppKit import NSApplication, NSWindow, NSColor, NSBackingStoreBuffered
from Foundation import NSMakeRect
from PyObjCTools import AppHelper
app = NSApplication.sharedApplication(); app.setActivationPolicy_(1)
w = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(NSMakeRect(80, 80, 300, 200), 0, NSBackingStoreBuffered, False)
w.setSharingType_(0)          # NSWindowSharingNone: hidden from screen capture
w.setLevel_(3)                # floating, always on top
w.setAlphaValue_(0.6)
w.setBackgroundColor_(NSColor.redColor())
w.orderFrontRegardless()
AppHelper.callLater(40, AppHelper.stopEventLoop)
AppHelper.runEventLoop()
"""

HELPER_INJECT = r"""
import time
from pynput.keyboard import Controller, Key
k = Controller()
for _ in range(6):
    k.press(Key.shift); k.release(Key.shift); time.sleep(0.1)
"""

## change1
# helper function for manual child process matching due to virtual env
def tree_pids(pid):
    try:
        p = psutil.Process(pid)
        return {pid} | {c.pid for c in p.children(recursive=True)}
    except Exception:
        return {pid}
    

def selftest():
    """Start fake 'cheat' helpers and check each is detected. Safe: everything stays on this machine."""
    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")

    print(f"Platform: {PLAT.name}   Python: {sys.executable}")
    perm_ok, perm_msg = PLAT.input_permission()
    print(f"Input permission: {'ok' if perm_ok else perm_msg}")
    print(f"Monitors: {PLAT.monitors()}   VM: {PLAT.vm_signals()}")

    baseline = snapshot_keys()
    listening = start_input_listeners()
    helpers = []
    ip = lan_ip()
    port = None
    if ip:
        h = subprocess.Popen([sys.executable, "-c", HELPER_NET, ip], stdout=subprocess.PIPE, text=True)
        helpers.append(h)
        port = (h.stdout.readline() or "").strip()
    overlay_code = HELPER_OVERLAY_WIN if IS_WIN else HELPER_OVERLAY_MAC if IS_MAC else None
    ov = subprocess.Popen([sys.executable, "-c", overlay_code]) if overlay_code else None
    if ov:
        helpers.append(ov)

    if listening:
        print("\nType a few keys and move the mouse for 5 seconds (checks REAL input is seen)...")
        time.sleep(5)
        with _lock:
            real_before, inj_before = real_count, injected_count
        subprocess.run([sys.executable, "-c", HELPER_INJECT], timeout=30)
        time.sleep(1)
        with _lock:
            real_after, inj_after = real_count, injected_count
    else:
        time.sleep(3)

    flags, _ = run_checks(baseline)

    ## change2
    # types_for = lambda pid: {f["type"] for f in flags if f.get("pid") == pid}
    types_for = lambda pid: {f["type"] for f in flags if f.get("pid") in tree_pids(pid)}

    print("\nResults:")
    if ip and port:
        t = types_for(helpers[0].pid)
        check("script on network detected (script_network)", "script_network" in t)
        check("new program on network detected (new_proc_network)", "new_proc_network" in t)

        ## change3
        # rp = [f for f in flags if f["type"] == "remote_port" and f.get("pid") == helpers[0].pid]
        rp = [f for f in flags if f["type"] == "remote_port" and f.get("pid") in tree_pids(helpers[0].pid)]
        
        check(f"outbound remote port {port}", bool(rp and rp[0]["outbound"]))
        check(f"inbound connection on remote port {port}", bool(rp and rp[0]["inbound"]))
    else:
        check("network helper started", False, "(no LAN IP / ports 5900,5901,5500 busy)")
    if ov and getattr(PLAT, "overlay_blind", False):
        check("window hidden from screen capture (hidden_overlay)", False,
              "(Screen Recording permission missing: check is blind, overlay_check_blind raised)")
    elif ov:
        t = types_for(ov.pid)
        check("window hidden from screen capture (hidden_overlay)", "hidden_overlay" in t,
              "" if "hidden_overlay" in t else "(see notes in the README section)")
    if listening:
        check("real input seen", real_before > 0, f"(real events: {real_before}; 0 = permission missing or you didn't type)")
        check("injected input detected", inj_after - inj_before >= 3,
              f"(injected events: {inj_after - inj_before}, real during injection: {real_after - real_before})")
    else:
        print("  [SKIP] input checks (pynput unavailable or unsupported platform)")

    print("\nAll flags raised during the test:")
    for f in flags:
        if f["type"] != "unreadable_processes":
            print("   ", json.dumps(f)[:200])
    for h in helpers:
        h.kill()
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return all(results)


# ------------------------------ MAIN -----------------------------------
CONSENT = """
This test uses a monitoring program. While the test is running it will check:
  - which programs are running, whether they use the network, and who signed them
  - whether remote-control software, a remote session, or a screen-capture-hidden window is active
  - number of screens, virtual machine signs, and whether keyboard/mouse input is injected
    (only counts of events are kept - never which keys you press)
  - window titles, including browser tabs, for names of interview-assistant tools
    (only matching titles are kept)
Results are sent to the test provider and reviewed by a person before any decision.
Press Enter to agree and run the system check, or close this window to decline.
"""


def describe_blocker(b):
    t = b["type"]
    if t == "extra_monitor":
        return f"Disconnect extra screens (found {b['count']})"
    if t == "vm_running":
        v = b.get("vm", "")
        if v == "vmmemwsl":
            how = "WSL is running: open a terminal and run  wsl --shutdown"
        elif "docker" in v or v == "vfkit":
            how = "Docker Desktop's VM is running: quit Docker Desktop"
        elif v.startswith("windowssandbox"):
            how = "Windows Sandbox is running: close it"
        elif v in ("vmwp", "vmmem"):
            how = "A Hyper-V VM (or WSL/Docker/Sandbox) is running: shut it down (wsl --shutdown, quit Docker)"
        else:
            how = "Close the virtual machine"
        return f"{b.get('proc')}  [virtual machine running]  {how}"
    if t == "remote_session" and "exe" not in b:
        return "A remote desktop / screen-sharing session is active. End it and run the test on the machine itself."
    if t == "remote_session" and b.get("via") == "macos_screen_sharing":
        return (f"{b.get('proc')}  [Mac screen sharing active]  End the screen-sharing session "
                "(Screen Sharing app or Messages) and quit the Screen Sharing app")
    if t == "overlay_check_blind":
        return ("Screen Recording permission is missing, so hidden windows cannot be checked. Grant it to the app "
                "you run this from (Terminal, iTerm or VS Code) in System Settings > Privacy & Security > "
                "Screen Recording, then restart the monitor")
    if t == "sharing_enabled":
        return (f"{b.get('service')} is turned on: switch it off in System Settings > General > Sharing, "
                "then re-check")
    labels = {"unsigned_program": "unsigned program", "unsigned_network": "unsigned program using the network",
              "hidden_overlay": "window hidden from screen capture", "cheat_tool": "interview-assistant tool",
              "cheat_site": "interview-assistant site or window",
              "remote_identity": "remote-access tool",
              "remote_port": "remote-access port in use", "script_network": "script using the network",
              "remote_session": "remote session in progress"}
    extra = f" '{b['title']}'" if b.get("title") else (f" {b['cmd']}" if b.get("cmd") else "")
    return f"{b.get('proc')}  ({b.get('exe', '')})  [{labels.get(t, t)}]{extra}"


def quick_check():
    """One scan, no consent prompt, no monitoring loop: print FLAGGED / CLEAN and the reasons.
    Exit code 0 = clean, 1 = flagged. Meant for the one-line run straight from the server:
        python3 -c "$(curl -fsSL https://HOST/proctor_monitor.py)" --check"""
    print(f"Platform: {PLAT.name}   Python: {platform.machine()} {sys.version.split()[0]}")
    vm_strong, vm_weak = PLAT.vm_signals()
    flags, _ = run_checks(baseline=set())
    reasons = []
    if vm_strong:
        reasons.append("Running inside a virtual machine (%s)" % ", ".join(vm_strong))
    if IS_WIN and BLOCK_HYPERV_FEATURE:
        reasons += ["Windows feature that runs VMs is on: " + w.split(":", 1)[1]
                    for w in vm_weak if w.startswith("feature:")]
    perm_ok, perm_msg = PLAT.input_permission()
    for b in flags:
        if b["type"] in PRECHECK_BLOCKERS:
            line = describe_blocker(b)
            if line not in reasons:
                reasons.append(line)
    if reasons:
        print("\nRESULT: FLAGGED")
        for r in reasons:
            print(" - " + r)
    else:
        print("\nRESULT: CLEAN (nothing obvious found)")
    if not perm_ok:
        print("\nNote: " + perm_msg)
    return 1 if reasons else 0


def main():
    global SERVER_URL, SESSION_ID, SESSION_TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--session", default=SESSION_ID)
    ap.add_argument("--token", default=SESSION_TOKEN)
    ap.add_argument("--server", default=SERVER_URL)
    ap.add_argument("--find")
    ap.add_argument("--debug-net", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--check", action="store_true", help="one scan, print FLAGGED / CLEAN, exit 1 if flagged")
    a = ap.parse_args()
    SERVER_URL, SESSION_ID, SESSION_TOKEN = a.server, a.session, a.token

    if a.find is not None:
        return find_proc(a.find)
    if a.debug_net:
        return debug_net()
    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if a.check:
        sys.exit(quick_check())
    if not (IS_WIN or IS_MAC):
        print("This monitor supports Windows and macOS only (Linux: --selftest/--find/--debug-net).")
        sys.exit(1)

    input(CONSENT)

    print("Running system check (about 10-30 seconds the first time)...")
    vm_strong, vm_weak = PLAT.vm_signals()
    if vm_strong:
        print("Virtual machine detected (%s). Please run the test on your real computer." % ", ".join(vm_strong))
        sys.exit(1)
    feats = [w.split(":", 1)[1] for w in vm_weak if w.startswith("feature:")]
    if BLOCK_HYPERV_FEATURE and feats:
        print("These Windows features let virtual machines run and are not allowed for this test:\n  "
              + "\n  ".join(feats) +
              "\nTurn them off in 'Turn Windows features on or off' (Hyper-V, Virtual Machine Platform,"
              "\nWindows Sandbox, Windows Hypervisor Platform), restart the computer, then run the check again.")
        sys.exit(1)

    perm_ok, perm_msg = PLAT.input_permission()
    if not perm_ok:
        print("\nWARNING: " + perm_msg + "\nThe session will be flagged until this is fixed.\n")
    print("  VM check done. Scanning programs...")
    while True:
        flags, _ = run_checks(baseline=set())
        blockers = [f for f in flags if f["type"] in PRECHECK_BLOCKERS]
        if not blockers:
            break
        print("\nPlease close or fix the following, then press Enter to re-check:")
        seen = set()
        for b in blockers:
            line = describe_blocker(b)
            if line not in seen:
                seen.add(line)
                print(" - " + line)
        input()

    baseline = snapshot_keys()
    start_input_listeners()
    threading.Thread(target=overlay_watch, daemon=True).start()
    print("System check passed. Monitoring is active. You can start the test.\n")

    seq, last_injected, hb_failed, upload_streak = 0, 0, False, 0
    last_sent, last_t = psutil.net_io_counters().bytes_sent, time.time()
    session_counts, max_score, monitor_hash = {}, 0, own_hash()
    while True:
        seq += 1
        flags, monitors = run_checks(baseline)

        now = time.time()
        sent_now = psutil.net_io_counters().bytes_sent
        rate = (sent_now - last_sent) / max(now - last_t, 0.1)
        last_sent, last_t = sent_now, now
        upload_streak = upload_streak + 1 if rate > UPLOAD_ALERT_BPS else 0
        if upload_streak >= UPLOAD_STREAK_NEEDED:
            flags.append({"type": "sustained_upload", "kb_per_s": round(rate / 1024)})

        with _lock:
            inj_now, real_now, by_pid = injected_count, real_count, dict(injected_by)
        injected_delta = inj_now - last_injected
        last_injected = inj_now
        score = score_of(flags, injected_delta, vm_strong, vm_weak, hb_failed)
        max_score = max(max_score, score)
        for t in {f["type"] for f in flags}:
            session_counts[t] = session_counts.get(t, 0) + 1
        inj_names = {}
        for pid, n in by_pid.items():
            try:
                inj_names[psutil.Process(pid).name()] = n
            except Exception:
                inj_names[str(pid)] = n
        payload = {
            "session": SESSION_ID, "seq": seq, "ts": now, "platform": PLAT.name,
            "score": score, "level": level(score), "max_score": max_score,
            "monitors": monitors, "injected_delta": injected_delta, "injected_by": inj_names,
            "real_input_total": real_now, "upload_kbps": round(rate / 1024),
            "vm_weak": vm_weak, "flags": flags, "session_flag_counts": session_counts,
            "monitor_sha256": monitor_hash,
        }
        hb_failed = not send(payload)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
