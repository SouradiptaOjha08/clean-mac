#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clean_mac — Ultimate macOS Cleaner & Junk Hunter (v3.0)

Scans every area of macOS where junk, leftovers and unnecessary files pile up,
and gives a specific recommendation for each item it finds:

  ✔ RECOMMENDED  safe to remove: regenerated automatically, or plain junk
  ? REVIEW       probably not needed, but it is your data / your call
  ■ KEEP         shown for information; removing it is possible but not advised

Areas: Trash · System & user caches · Logs & crash reports · Temp files ·
Browsers · App internal caches · Old versions & update leftovers ·
Uninstalled-app leftovers · Startup items, plug-ins & receipts ·
Unused applications · Code editors · Developer tools & package caches ·
Project junk · Docker/Colima · Xcode & simulators · Apple apps & devices ·
Downloads · Large files · Duplicate files · Clutter · APFS snapshots ·
Maintenance tasks.

Safety:
  * hard-coded protected locations (keychains, iCloud, Mail, Photos, .ssh,
    .git, system folders, ...) can never be deleted
  * symlinks are never followed
  * personal files (downloads, large files, duplicates, apps) go to the Trash
  * caches belonging to running apps are skipped unless you say otherwise
  * every action is logged to ~/Library/Logs/clean_mac/clean_mac.log
  * dry-run mode, and an ignore list in ~/.clean_mac_ignore

Usage:
  clean_mac                          interactive dashboard
  clean_mac --scan                   full report, changes nothing
  clean_mac --clean recommended      remove every RECOMMENDED item (asks once)
  clean_mac --clean all              RECOMMENDED + REVIEW items
  clean_mac --area caches,logs ...   limit to some areas (see --list-areas)
  clean_mac --dry-run --clean recommended     simulate only
Options: --yes --sudo --force-running --large-mb N --dupe-mb N --old-days N
         --unused-days N --json FILE --no-color
"""

import argparse
import datetime as _dt
import fnmatch
import glob
import hashlib
import json
import os
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

VERSION = "3.0"

# =============================================================================
# Basic process helpers
# =============================================================================


def run(cmd: List[str], timeout: int = 60, env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """Run a command and capture output. Never raises."""
    try:
        full_env = None
        if env:
            full_env = dict(os.environ)
            full_env.update(env)
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace", env=full_env, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "command not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as e:  # pragma: no cover - defensive
        return 1, "", str(e)


def _resolve_user() -> Tuple[str, int, str]:
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() == 0 and sudo_user and sudo_user != "root":
        try:
            pw = pwd.getpwnam(sudo_user)
            return pw.pw_dir, pw.pw_uid, pw.pw_name
        except KeyError:
            pass
    pw = pwd.getpwuid(os.getuid())
    return pw.pw_dir, pw.pw_uid, pw.pw_name


HOME, UID, USER = _resolve_user()
HOME = os.path.realpath(HOME)
IS_ROOT = os.geteuid() == 0
LIB = os.path.join(HOME, "Library")
AS = os.path.join(LIB, "Application Support")
CACHES = os.path.join(LIB, "Caches")
NOW = time.time()
DAY = 86400.0
LOG_DIR = os.path.join(LIB, "Logs", "clean_mac")
LOG_FILE = os.path.join(LOG_DIR, "clean_mac.log")
IGNORE_FILE = os.path.join(HOME, ".clean_mac_ignore")
LSREGISTER = ("/System/Library/Frameworks/CoreServices.framework/Frameworks/"
              "LaunchServices.framework/Support/lsregister")


def user_cmd(cmd: List[str]) -> List[str]:
    """When running under sudo, run user-level tools (brew, docker...) as the real user."""
    if IS_ROOT and USER != "root":
        return ["sudo", "-u", USER, "-H"] + cmd
    return cmd


def _darwin_dir(name: str) -> str:
    rc, out, _ = run(user_cmd(["getconf", name]), 10)
    v = out.strip()
    if rc == 0 and v and os.path.isdir(v):
        return os.path.realpath(v)
    return ""


USER_TMP = _darwin_dir("DARWIN_USER_TEMP_DIR")
USER_CACHE = _darwin_dir("DARWIN_USER_CACHE_DIR")

# =============================================================================
# Output formatting
# =============================================================================

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN = ("\033[31m", "\033[32m", "\033[33m",
                                           "\033[34m", "\033[35m", "\033[36m")


def c(text, *codes) -> str:
    if not USE_COLOR or not codes:
        return str(text)
    return "".join(codes) + str(text) + RESET


def human(n: float) -> str:
    """Finder-style (base-1000) sizes."""
    if not n or n <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    i = 0
    while f >= 1000 and i < len(units) - 1:
        f /= 1000.0
        i += 1
    return ("%.0f %s" if i < 2 else "%.1f %s") % (f, units[i])


def short(p: str) -> str:
    if p == HOME:
        return "~"
    if p.startswith(HOME + "/"):
        return "~" + p[len(HOME):]
    return p


def trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: max(1, n - 1)] + "…"


def term_width() -> int:
    try:
        return max(70, min(140, shutil.get_terminal_size((100, 30)).columns))
    except Exception:
        return 100


def parse_size(s: str) -> int:
    """Parse '1.2GB', '532 MB', '12kB' into bytes."""
    m = re.search(r"([\d.]+)\s*([KMGTP]?i?B)", s or "", re.I)
    if not m:
        return 0
    try:
        val = float(m.group(1))
    except ValueError:
        return 0
    unit = m.group(2).upper().replace("I", "")
    mult = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15}.get(unit, 1)
    return int(val * mult)


def parse_version(v) -> Tuple[int, ...]:
    if not v:
        return ()
    return tuple(int(n) for n in re.findall(r"\d+", str(v))[:6])


# =============================================================================
# Filesystem helpers
# =============================================================================

_DU: Dict[str, int] = {}


def du(path: str) -> int:
    """Real disk usage in bytes (allocated blocks), never follows symlinks."""
    if path in _DU:
        return _DU[path]
    try:
        st = os.lstat(path)
    except OSError:
        _DU[path] = 0
        return 0
    total = st.st_blocks * 512
    if stat.S_ISDIR(st.st_mode):
        seen: Set[Tuple[int, int]] = set()
        stack = [path]
        while stack:
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            s = e.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if stat.S_ISDIR(s.st_mode):
                            total += s.st_blocks * 512
                            stack.append(e.path)
                        else:
                            if s.st_nlink > 1:
                                k = (s.st_dev, s.st_ino)
                                if k in seen:
                                    continue
                                seen.add(k)
                            total += s.st_blocks * 512
            except OSError:
                continue
    _DU[path] = total
    return total


def du_clear():
    _DU.clear()


def isdir(p: str) -> bool:
    return os.path.isdir(p) and not os.path.islink(p)


def listdir(d: str) -> List[str]:
    try:
        return sorted(os.listdir(d))
    except OSError:
        return []


def mtime(p: str) -> float:
    try:
        return os.lstat(p).st_mtime
    except OSError:
        return NOW


def newest_mtime(p: str, depth: int = 1, limit: int = 400) -> float:
    """Most recent modification time of p and its descendants (bounded)."""
    best = mtime(p)
    if depth <= 0 or not isdir(p):
        return best
    count = 0
    stack = [(p, 0)]
    while stack:
        d, lvl = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    count += 1
                    if count > limit:
                        return best
                    try:
                        s = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if s.st_mtime > best:
                        best = s.st_mtime
                    if stat.S_ISDIR(s.st_mode) and lvl + 1 < depth:
                        stack.append((e.path, lvl + 1))
        except OSError:
            continue
    return best


def age_days(p: str) -> float:
    return max(0.0, (NOW - mtime(p)) / DAY)


def children(d: str, min_age_days: float = 0.0, exclude=(), depth_for_age: int = 1) -> List[str]:
    """Direct children of d (optionally only those untouched for min_age_days)."""
    out = []
    for n in listdir(d):
        if n in exclude:
            continue
        p = os.path.join(d, n)
        if min_age_days > 0 and newest_mtime(p, depth=depth_for_age) > NOW - min_age_days * DAY:
            continue
        out.append(p)
    return out


def read_plist(path: str) -> Optional[dict]:
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return None


def read_json(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def bundle_info(path: str) -> Dict[str, str]:
    for rel in ("Contents/Info.plist", "Info.plist", "Resources/Info.plist"):
        info = read_plist(os.path.join(path, rel))
        if info:
            return {
                "bid": str(info.get("CFBundleIdentifier") or ""),
                "name": str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or ""),
                "version": str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or ""),
                "exe": str(info.get("CFBundleExecutable") or ""),
            }
    return {"bid": "", "name": "", "version": "", "exe": ""}


def disk_free() -> Tuple[int, int]:
    try:
        st = os.statvfs(HOME)
        return st.f_frsize * st.f_bavail, st.f_frsize * st.f_blocks
    except OSError:
        return 0, 0


def under(p: str, root: str) -> bool:
    root = root.rstrip("/")
    if not root:
        return p != "/"
    return p.startswith(root + "/")


def _n(p: str) -> str:
    return os.path.normpath(p)


# =============================================================================
# Safety guard — nothing is ever deleted without passing is_safe()
# =============================================================================


def _protected_exact() -> Set[str]:
    s = {"/", "/System", "/Library", "/Applications", "/Users", "/private", "/private/var",
         "/private/tmp", "/private/var/log", "/usr", "/usr/local", "/usr/local/bin", "/bin",
         "/sbin", "/opt", "/opt/homebrew", "/opt/homebrew/bin", "/Volumes", "/Users/Shared",
         HOME, LIB, AS, CACHES, os.path.join(HOME, ".Trash"), "/Library/Caches",
         "/Library/Logs", "/Library/Application Support", "/Library/LaunchAgents",
         "/Library/LaunchDaemons", "/Library/PrivilegedHelperTools", "/Library/Audio",
         "/Library/Audio/Plug-Ins", "/Library/Audio/Plug-Ins/HAL", "/Library/Internet Plug-Ins",
         "/Library/PreferencePanes", "/Library/Logs/DiagnosticReports"}
    for x in ("Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Public",
              "Applications", "Developer", "Sites"):
        s.add(os.path.join(HOME, x))
    for x in listdir(LIB):
        s.add(os.path.join(LIB, x))
    for x in ("Containers", "Group Containers"):
        s.add(os.path.join(LIB, x))
    if USER_TMP:
        s.add(USER_TMP)
    if USER_CACHE:
        s.add(USER_CACHE)
    return {_n(x) for x in s}


PROTECTED_EXACT = _protected_exact()
PROTECTED_TREES = [_n(p) for p in [
    os.path.join(HOME, ".ssh"), os.path.join(HOME, ".gnupg"), os.path.join(HOME, ".claude"),
    os.path.join(LIB, "Keychains"), os.path.join(LIB, "Mobile Documents"),
    os.path.join(LIB, "CloudStorage"), os.path.join(LIB, "Mail"), os.path.join(LIB, "Messages"),
    os.path.join(LIB, "Accounts"), os.path.join(LIB, "Calendars"), os.path.join(LIB, "Safari"),
    os.path.join(LIB, "IdentityServices"), os.path.join(LIB, "Photos"), os.path.join(LIB, "Biome"),
    os.path.join(LIB, "Daemon Containers"), os.path.join(LIB, "Metadata"),
    os.path.join(LIB, "Group Containers", "group.com.apple.notes"),
    "/System", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/usr/share",
    "/private/etc", "/private/var/db", "/private/var/root", "/Library/Apple", "/Library/Keychains",
    "/Library/Developer/CommandLineTools", "/Library/Frameworks", "/Library/Extensions",
    "/Library/SystemExtensions",
]]
ALLOWED_TREES = [_n(p) for p in [
    HOME, "/Applications", "/Library/Caches", "/Library/Logs", "/private/var/log",
    "/Library/Application Support", "/Library/LaunchAgents", "/Library/LaunchDaemons",
    "/Library/PrivilegedHelperTools", "/Library/Audio/Plug-Ins", "/Library/Audio/Apple Loops",
    "/Library/Internet Plug-Ins", "/Library/PreferencePanes", "/Library/Screen Savers",
    "/Library/QuickLook", "/Library/Spotlight", "/Library/Input Methods", "/Library/Google",
    "/Users/Shared", "/private/tmp", "/usr/local/bin", "/opt/homebrew/bin",
] + ([USER_TMP] if USER_TMP else [])]
MEDIA_LIBS = (".photoslibrary", ".musiclibrary", ".tvlibrary", ".photolibrary", ".aplibrary")


def is_safe(path: str, action: str = "delete") -> Tuple[bool, str]:
    if not path or not os.path.isabs(path):
        return False, "not an absolute path"
    p = _n(path)
    try:
        rp = _n(os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p)))
    except Exception:
        return False, "cannot resolve path"
    for q in {p, rp}:
        if q in PROTECTED_EXACT:
            return False, "protected location"
        for t in PROTECTED_TREES:
            if q == t or under(q, t):
                return False, "inside protected area %s" % short(t)
        parts = q.split("/")
        if ".git" in parts:
            return False, "inside a .git repository folder"
        if any(x.endswith(MEDIA_LIBS) for x in parts):
            return False, "inside a media library"
    if not any(under(rp, t) for t in ALLOWED_TREES):
        return False, "outside the areas clean_mac may touch"
    if os.path.dirname(rp) == HOME and isdir(rp) and action != "trash":
        return False, "top-level home folder (only moving to Trash is allowed)"
    if under(rp, "/Applications"):
        rel = rp[len("/Applications/"):]
        if not rel.endswith(".app") or rel.count("/") > 1:
            return False, "only .app bundles may be removed from /Applications"
        bid = bundle_info(rp).get("bid", "").lower()
        if bid.startswith("com.apple.") and not bid.startswith("com.apple.safari.webapp"):
            return False, "Apple application"
    return True, ""


# =============================================================================
# Ignore list & log
# =============================================================================


def load_ignore() -> List[str]:
    pats = []
    try:
        with open(IGNORE_FILE, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s and not s.startswith("#"):
                    pats.append(s)
    except OSError:
        pass
    return pats


def is_ignored(path: str, pats: List[str]) -> bool:
    if not pats:
        return False
    p = _n(path)
    low = p.lower()
    for pat in pats:
        if pat.startswith(("/", "~")):
            e = _n(os.path.expanduser(pat))
            if any(ch in e for ch in "*?["):
                if fnmatch.fnmatch(p, e):
                    return True
            elif p == e or p.startswith(e + "/") or e.startswith(p + "/"):
                return True  # also protects parents of an ignored path
        else:
            if any(ch in pat for ch in "*?["):
                if fnmatch.fnmatch(os.path.basename(p), pat) or fnmatch.fnmatch(p, pat):
                    return True
            elif pat.lower() in low:
                return True
    return False


def add_ignore(entry: str) -> bool:
    try:
        new = not os.path.exists(IGNORE_FILE)
        with open(IGNORE_FILE, "a", encoding="utf-8") as fh:
            if new:
                fh.write("# clean_mac ignore list — one path, glob or keyword per line\n")
            fh.write(entry.replace(HOME, "~", 1) + "\n")
        return True
    except OSError:
        return False


class Log:
    def __init__(self):
        self.fh = None
        try:
            os.makedirs(LOG_DIR, exist_ok=True)
            self.fh = open(LOG_FILE, "a", encoding="utf-8")
            if IS_ROOT:
                try:
                    os.chown(LOG_FILE, UID, -1)
                    os.chown(LOG_DIR, UID, -1)
                except OSError:
                    pass
        except OSError:
            self.fh = None

    def write(self, kind: str, text: str):
        if self.fh:
            try:
                self.fh.write("%s %-8s %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), kind, text))
                self.fh.flush()
            except OSError:
                pass


LOG = Log()

# =============================================================================
# Data model
# =============================================================================

REC, REV, KEEP = "RECOMMENDED", "REVIEW", "KEEP"
REC_STYLE = {REC: ("✔ RECOMMENDED", GREEN), REV: ("? REVIEW     ", YELLOW), KEEP: ("■ KEEP       ", CYAN)}
REC_ORDER = {REC: 0, REV: 1, KEEP: 2}

ACT_DELETE = "delete"        # permanent delete of each path
ACT_TRASH = "trash"          # move each path to the Trash (recoverable)
ACT_CONTENTS = "contents"    # delete everything inside a directory (admin, unreadable dirs)
ACT_CMD = "cmd"              # run commands
ACT_LAUNCHD = "launchd"      # unload launch agent/daemon, then delete
ACT_EMPTY_TRASH = "empty_trash"
ACT_NONE = "none"            # information only
PATH_ACTIONS = (ACT_DELETE, ACT_TRASH, ACT_CONTENTS, ACT_LAUNCHD)


@dataclass
class Finding:
    area: str
    title: str
    rec: str
    reason: str
    paths: List[str] = field(default_factory=list)
    size: int = 0
    action: str = ACT_DELETE
    location: str = ""
    impact: str = ""
    cmds: List[List[str]] = field(default_factory=list)
    sudo: bool = False
    owners: List[str] = field(default_factory=list)   # bundle ids / names of owning app
    running: str = ""
    keep_zero: bool = False
    status: str = ""
    freed: int = 0
    note: str = ""

    def where(self) -> str:
        return self.location or (self.paths[0] if self.paths else (" ".join(self.cmds[0]) if self.cmds else ""))


def mk(area: str, title: str, rec: str, reason: str, paths=None, size: Optional[int] = None, **kw) -> Finding:
    paths = list(paths or [])
    f = Finding(area=area, title=title, rec=rec, reason=reason, paths=paths, **kw)
    f.size = int(size) if size is not None else sum(du(p) for p in paths)
    return f


AREAS = [
    ("trash", "Trash", "Files you already deleted"),
    ("caches", "System & User Caches", "~/Library/Caches and /Library/Caches"),
    ("logs", "Logs & Crash Reports", "App logs, diagnostic reports, rotated system logs"),
    ("temp", "Temporary Files", "Stale files in your temporary folders"),
    ("browsers", "Browsers", "Safari, Chrome, Brave, Edge, Firefox, Arc, Opera, Vivaldi …"),
    ("appcache", "App Internal Caches", "Electron/Chromium app caches, sandboxed app caches"),
    ("updates", "Old Versions & Update Leftovers", "Previous app versions, updater payloads, Homebrew"),
    ("leftovers", "Uninstalled App Leftovers", "Data of apps that are no longer installed"),
    ("startup", "Startup Items, Plug-ins & Receipts", "Broken/orphan launch agents, helpers, plug-ins, pkg receipts"),
    ("unused", "Unused Applications", "Apps you have not opened in months"),
    ("editors", "Code Editors", "VS Code family: old extensions, VSIX cache, orphan workspace data"),
    ("dev", "Developer Tools & Package Caches", "npm, pip, Maven, Gradle, Go, Cargo, JetBrains, Jenkins, SDKs …"),
    ("projects", "Project Junk", "node_modules, venvs, build outputs, __pycache__ in your projects"),
    ("docker", "Docker / Colima", "Images, containers, volumes, build cache, VM disk"),
    ("xcode", "Xcode & Simulators", "DerivedData, device support, simulators, archives"),
    ("apple", "Apple Apps & Devices", "iOS backups & firmware, Mail downloads, wallpapers, media"),
    ("downloads", "Downloads Folder", "Used installers, incomplete and old downloads"),
    ("large", "Large Files", "Big files in your home folder"),
    ("dupes", "Duplicate Files", "Identical files stored more than once"),
    ("clutter", "Clutter", ".DS_Store, broken links, empty folders, temp Office files, old screenshots"),
    ("snapshots", "APFS Local Snapshots", "Time Machine local snapshots holding 'purgeable' space"),
    ("maint", "Maintenance Tasks", "QuickLook, LaunchServices, DNS, fonts, memory, Spotlight"),
]
AREA_TITLE = {k: t for k, t, _ in AREAS}
AREA_DESC = {k: d for k, _, d in AREAS}
WALK_AREAS = {"projects", "clutter", "large", "dupes"}
# Specific scanners run first and "claim" paths so generic scanners don't double count.
SCAN_ORDER = ["trash", "snapshots", "browsers", "editors", "xcode", "docker", "dev", "updates",
              "apple", "logs", "temp", "appcache", "caches", "leftovers", "startup", "downloads",
              "projects", "clutter", "large", "dupes", "unused", "maint"]

# =============================================================================
# Knowledge: Apple names, tokens, installed-app index
# =============================================================================

TLDS = {"com", "org", "net", "io", "co", "de", "uk", "me", "app", "dev", "ai", "eu", "fr", "us", "ru",
        "cn", "jp", "in", "info", "biz", "tv", "so", "sh", "xyz", "cc", "gg", "to", "ch", "nl", "se",
        "it", "es", "pl", "br", "ca", "au", "fi", "dk", "no", "at", "be", "kr", "tw", "hk", "sg", "ly",
        "im", "is", "la", "md", "gl", "ws", "pro", "one", "tech", "cloud", "group", "edu", "gov", "eu"}
GENERIC_TOKENS = {
    "app", "apps", "mac", "macos", "osx", "desktop", "helper", "helpers", "agent", "inc", "ltd", "llc",
    "gmbh", "www", "the", "launcher", "widget", "widgets", "extension", "extensions", "daemon",
    "service", "services", "plugin", "plugins", "group", "dev", "pro", "lite", "free", "client", "web",
    "tools", "tool", "cli", "software", "studio", "update", "updater", "for", "beta", "browser",
    "installer", "login", "loginitem", "main", "core", "shared", "share", "kit", "framework",
    "library", "data", "cache", "caches", "support", "settings", "preferences", "prefs", "menu", "bar",
    "menubar", "mini", "plus", "new", "old", "test", "demo", "system", "manager", "utility",
    "utilities", "open", "file", "files", "online", "player", "edition", "community", "assistant",
    "storage", "sync", "notification", "notifications", "intents", "intent",
    "xpc", "launch", "auto", "start", "startup", "com", "net", "org", "default", "local", "user",
    "users", "global", "config", "private", "public", "sdk", "api", "engine", "runtime", "native",
    "messaging", "host", "share", "finder", "sidebar", "today", "quicklook", "preview", "thumbnail",
}
APPLE_NAMES = {
    "addressbook", "animoji", "appstore", "app store", "apple", "applepushservice", "btserver",
    "callhistorydb", "callhistorytransactions", "clouddocs", "crashreporter", "differentialprivacy",
    "dock", "facetime", "fileprovider", "icloud", "ilifemediabrowser", "knowledge", "mobilesync",
    "proapps", "script editor", "syncservices", "ubiquity", "accounts", "askpermission", "coreparsec",
    "diskimages", "familycircle", "photos", "mail", "notes", "news", "safari", "siri", "shortcuts",
    "stocks", "weather", "maps", "quicktime", "preview", "textedit", "gamekit", "passes", "contacts",
    "calendars", "reminders", "tips", "voice memos", "voicememos", "podcasts", "music", "tv", "books",
    "ibooks", "garageband", "imovie", "keynote", "pages", "numbers", "networkserviceproxy",
    "caches", "cloudkit", "spotlight", "wallpaper", "screen time", "screentime", "identityservices",
    "rapport", "sharing", "audio", "coreservices", "image capture", "printers", "colorpickers",
    "colorsync", "keyboard services", "fonts", "input methods", "spelling", "sounds", "speech",
    "autosave information", "assistant", "assistants", "biome", "dictionaries", "frameworks",
    "personalizationportrait", "family", "feedback assistant", "terminal", "console", "automator",
    "applescript", "services", "workflows", "keychains", "containers", "group containers",
    "application support", "preferences", "logs", "launchagents", "cookies", "webkit", "httpstorages",
    "saved application state", "metadata", "mobile documents", "cloudstorage", "sharedfilelist",
    "trial", "studentd", "default.store", "sync", "suggestions", "intelligenceplatform",
    "intelligence", "translation", "homekit", "home", "freeform", "journal", "passwords",
    "findmy", "find my", "clock", "games", "apple intelligence", "messages", "accessibility",
    "com.apple", ".localized", "icdd", "itunes", "sc info", "library",
    "addressbook-v22", "bluetooth", "videoconference", "ubiquitous", "ckdatabase", "corespotlight",
    "sesstorage", "categories", "extensionscache", "assets", "com.apple.sharedfilelist", "callservices",
    "homeenergy", "tvappservices.container", "persona", "searchd", "sirikit", "geoservices",
}
OWNER_PROBES = [
    ("com.oracle.java", "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin"),
    ("com.oracle.oss.mysql", "/usr/local/mysql"),
    ("com.mysql", "/usr/local/mysql"),
    ("org.python.python", "/Library/Frameworks/Python.framework"),
    ("com.docker", "/Applications/Docker.app"),
    ("org.virtualbox", "/Applications/VirtualBox.app"),
    ("com.microsoft.autoupdate", "/Library/Application Support/Microsoft/MAU2.0"),
]
BID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9_-]+)+$")
TEAM_RE = re.compile(r"^[A-Z0-9]{10}\.")
HEXISH_RE = re.compile(r"^[0-9a-f-]{8,}$")


def name_tokens(s: str) -> Set[str]:
    out: Set[str] = set()
    if not s:
        return out
    low = s.lower()
    joined = re.sub(r"[^a-z0-9]", "", low)
    if len(joined) >= 3:
        out.add(joined)
        nd = re.sub(r"\d+$", "", joined)
        if len(nd) >= 3:
            out.add(nd)
    parts = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", s) + re.split(r"[^a-z0-9]+", low)
    for p in parts:
        p = re.sub(r"\d+$", "", p.lower())
        if len(p) >= 3 and p not in GENERIC_TOKENS:
            out.add(p)
    return {t for t in out if t and t not in GENERIC_TOKENS}


def is_apple(low: str) -> bool:
    if low.startswith(("com.apple", "apple.", "group.com.apple.", "tvappservices", "systemgroup.com.apple")):
        return True
    if low in APPLE_NAMES:
        return True
    if "." not in low and re.match(r"^[a-z]+d$", low) and len(low) <= 24:
        return True  # daemon-style folder names, e.g. "livefsd"
    return False


class AppIndex:
    """Everything that is installed: apps, embedded bundles, CLI tools, brew, editor extensions."""

    def __init__(self):
        self.bids: Set[str] = set()
        self.vendors: Set[str] = set()
        self.vendor_tokens: Set[str] = set()
        self.app_tokens: Set[str] = set()
        self.cli: Set[str] = set()
        self.apps: List[Tuple[str, Dict[str, str]]] = []
        self.bid_paths: Dict[str, str] = {}
        found: Set[str] = set()
        roots = ["/Applications", os.path.join(HOME, "Applications"), "/System/Applications",
                 "/System/Library/CoreServices", "/Applications/Setapp"]
        for r in roots:
            self._collect(r, 2, found)
        rc, out, _ = run(["mdfind", "kMDItemContentType == 'com.apple.application-bundle'"], 45)
        if rc == 0:
            for line in out.splitlines():
                p = line.strip()
                if not p.endswith(".app") or ".app/" in p:
                    continue
                if ("/Library/" in p or p.startswith(("/Users/Shared", "/private", "/System/Volumes"))
                        or "/.Trash/" in p or "/node_modules/" in p or "/DerivedData/" in p
                        or "/Downloads/" in p):
                    continue
                found.add(p)
        for p in sorted(found):
            self._add_app(p)
        self._add_cli()
        self.long_tokens = [t for t in self.app_tokens if len(t) >= 5]

    def _collect(self, root: str, depth: int, found: Set[str]):
        for n in listdir(root):
            p = os.path.join(root, n)
            if n.endswith(".app"):
                found.add(p)
            elif depth > 1 and isdir(p) and not n.startswith("."):
                self._collect(p, depth - 1, found)

    def _add_bid(self, bid: str):
        low = bid.lower().strip()
        if not low:
            return
        self.bids.add(low)
        comps = low.split(".")
        if len(comps) >= 2:
            self.vendors.add(".".join(comps[:2]))
            for x in comps[:2]:
                if x not in TLDS and x not in GENERIC_TOKENS and len(x) >= 3:
                    self.vendor_tokens.add(x)
        for x in comps[2:]:
            if not HEXISH_RE.match(x):
                self.app_tokens |= name_tokens(x)

    def _add_app(self, path: str):
        info = bundle_info(path)
        self.apps.append((path, info))
        if info["bid"]:
            self._add_bid(info["bid"])
            self.bid_paths.setdefault(info["bid"].lower(), path)
        for s in (os.path.basename(path)[:-4], info["name"], info["exe"]):
            self.app_tokens |= name_tokens(s)
        contents = os.path.join(path, "Contents")
        for sub in ("PlugIns", "Library/LoginItems", "XPCServices", "Library/LaunchServices",
                    "Helpers", "Library/Spotlight", "Library/QuickLook", "Library/SystemExtensions",
                    "Frameworks"):
            for n in listdir(os.path.join(contents, sub)):
                if n.endswith((".appex", ".app", ".xpc", ".mdimporter", ".qlgenerator", ".systemextension")):
                    b = bundle_info(os.path.join(contents, sub, n)).get("bid")
                    if b:
                        self.bids.add(b.lower())

    def _add_cli(self):
        dirs = set()
        for d in os.environ.get("PATH", "").split(":"):
            if d and (d.startswith(HOME) or d.startswith(("/opt/", "/usr/local"))):
                dirs.add(d)
        dirs |= {"/opt/homebrew/bin", "/usr/local/bin", os.path.join(HOME, ".local", "bin"),
                 os.path.join(HOME, "bin"), os.path.join(HOME, ".cargo", "bin"),
                 os.path.join(HOME, "go", "bin")}
        for d in dirs:
            for n in listdir(d):
                low = n.lower()
                self.cli.add(low)
                self.app_tokens |= name_tokens(n)
        for d in ("/opt/homebrew/Cellar", "/opt/homebrew/Caskroom", "/usr/local/Cellar", "/usr/local/Caskroom"):
            for n in listdir(d):
                self.cli.add(n.lower())
                self.app_tokens |= name_tokens(n)
        for ed in (".vscode", ".vscode-insiders", ".cursor", ".windsurf", ".antigravity", ".vscode-oss", ".kiro"):
            for n in listdir(os.path.join(HOME, ed, "extensions")):
                ident = re.sub(r"-\d+\.\d+.*$", "", n)
                if "." in ident:
                    pub, nm = ident.split(".", 1)
                    self.app_tokens |= name_tokens(nm)
                    if len(pub) >= 3:
                        self.vendor_tokens.add(pub.lower())

    def has_bid(self, bid: str) -> bool:
        return bid.lower() in self.bids

    def _app_token_match(self, t: str) -> bool:
        if t in self.app_tokens:
            return True
        if len(t) >= 5:
            for a in self.long_tokens:
                if t in a or a in t:
                    return True
        return False

    def owner(self, ident: str) -> str:
        """Return 'apple', 'installed', 'vendor' (same vendor still installed) or 'orphan'."""
        s = (ident or "").strip()
        s = re.sub(r"\.(plist|savedstate|binarycookies|app|appex|driver|prefpane|plugin|qlgenerator|"
                   r"mdimporter|saver|bundle|component|xpc|kext|workflow|sqlite3?)$", "", s, flags=re.I)
        if TEAM_RE.match(s):
            s = s[11:]
        low = s.lower()
        if low.startswith("group."):
            low = low[6:]
        if not low:
            return "installed"
        if is_apple(low):
            return "apple"
        for prefix, probe in OWNER_PROBES:
            if low.startswith(prefix) and os.path.exists(probe):
                return "installed"
        if low in self.cli:
            return "installed"
        if BID_RE.match(low):
            for b in self.bids:
                if low == b or low.startswith(b + ".") or b.startswith(low + "."):
                    return "installed"
            comps = [x for x in low.split(".") if x]
            sig = [x for x in comps if x not in TLDS and not HEXISH_RE.match(x)]
            for x in (sig[1:] if len(sig) > 1 else sig):
                for t in name_tokens(x):
                    if self._app_token_match(t):
                        return "installed"
            if ".".join(comps[:2]) in self.vendors:
                return "vendor"
            for x in sig:
                if x in self.vendor_tokens:
                    return "vendor"
            return "orphan"
        toks = name_tokens(s)
        if not toks:
            return "installed"  # can't judge → assume it is in use
        for t in toks:
            if self._app_token_match(t):
                return "installed"
        for t in toks:
            if t in self.vendor_tokens:
                return "vendor"
        return "orphan"


def running_apps() -> Tuple[Set[str], Set[str]]:
    bids: Set[str] = set()
    names: Set[str] = set()
    rc, out, _ = run(["lsappinfo", "list"], 15)
    for m in re.finditer(r'bundleID="([^"]+)"', out):
        bids.add(m.group(1).lower())
    for m in re.finditer(r'^\s*\d+\)\s+"([^"]+)"', out, re.M):
        names.add(m.group(1).lower())
    rc, out, _ = run(["ps", "-axo", "comm="], 15)
    for line in out.splitlines():
        n = os.path.basename(line.strip()).lower()
        if n:
            names.add(n)
    return bids, names


def has_full_disk_access() -> bool:
    for probe in (os.path.join(LIB, "Safari"), os.path.join(LIB, "Mail"),
                  "/Library/Application Support/com.apple.TCC"):
        if os.path.exists(probe):
            try:
                os.listdir(probe)
                return True
            except PermissionError:
                return False
            except OSError:
                continue
    return True


def alnum(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# =============================================================================
# Home folder walk (shared by Projects, Clutter, Large files, Duplicates)
# =============================================================================

PACKAGE_EXTS = (".app", ".photoslibrary", ".musiclibrary", ".tvlibrary", ".fcpbundle", ".logicx",
                ".band", ".imovielibrary", ".xcarchive", ".bundle", ".framework", ".plugin",
                ".kext", ".rtfd", ".key", ".pages", ".numbers", ".sparsebundle", ".photolibrary",
                ".utm", ".pvm", ".vmwarevm", ".playground", ".xcodeproj", ".xcworkspace", ".lrlibrary",
                ".lrdata", ".dtBase2", ".scriv")
PARTIAL_EXTS = (".crdownload", ".part", ".partial", ".download", ".opdownload", ".!ut", ".bc!")
OFFICE_EXTS = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf")
GRADLE_FILES = {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}
JS_BUILD_DIRS = {".next", ".nuxt", ".parcel-cache", ".turbo", ".svelte-kit", ".angular", ".expo", ".docusaurus"}
PY_TOOL_CACHES = {".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", ".pytype"}
SF_DATALESS = 0x40000000
PROJECT_MARKERS = {"package.json", "pom.xml", "Cargo.toml", "pyproject.toml", "setup.py", "go.mod", "Gemfile",
                   "composer.json", ".project", ".classpath", ".idea", "Makefile", "CMakeLists.txt",
                   "requirements.txt", "build.xml", "Package.swift", "Podfile", "pubspec.yaml", "mix.exs",
                   "deno.json", "tsconfig.json", ".metadata", "build.sbt", "Pipfile", "manage.py"} | GRADLE_FILES
CODE_ARTIFACTS = (".jar", ".class", ".dll", ".so", ".dylib", ".node", ".pyc", ".whl", ".o", ".a", ".war",
                  ".ear", ".aar", ".lib", ".exe", ".pdb", ".wasm", ".jmod")
PROJECT_EXT_MARKERS = (".xcodeproj", ".xcworkspace", ".iml", ".sln", ".csproj", ".code-workspace")


class HomeWalk:
    def __init__(self, large_mb: int, dupe_mb: float):
        self.large_threshold = int(large_mb * 1e6)
        self.dupe_min = int(max(0.01, dupe_mb) * 1e6)
        self.ds_store: List[str] = []
        self.appledouble: List[str] = []
        self.office_tmp: List[str] = []
        self.partial: List[str] = []
        self.broken: List[Tuple[str, bool]] = []
        self.empty_dirs: List[str] = []
        self.large: List[Tuple[int, str]] = []
        self.buckets: Dict[int, List[str]] = defaultdict(list)
        self.junk: List[Tuple[str, str, str, float]] = []   # kind, path, project_dir, stale_days
        self._dupes: Optional[List[List[str]]] = None
        self.skip_top = {os.path.join(HOME, "Library"), os.path.join(HOME, "Applications"),
                         os.path.join(HOME, ".Trash")}
        self._walk()

    def _walk(self):
        stack: List[Tuple[str, bool, bool, int]] = [(HOME, False, False, 0)]
        visited = 0
        while stack:
            d, in_repo, in_proj, depth = stack.pop()
            visited += 1
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError:
                continue
            names = {e.name for e in entries}
            repo = in_repo or (".git" in names)
            project = in_proj or bool(names & PROJECT_MARKERS) or any(x.endswith(PROJECT_EXT_MARKERS) for x in names)
            real = [e for e in entries if e.name not in (".DS_Store", ".localized", "Icon\r")]
            if not real and depth >= 2 and not repo and not project and _n(d) not in PROTECTED_EXACT:
                self.empty_dirs.append(d)
            newest = 0.0
            stats = []
            for e in entries:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                stats.append((e, st))
            junk_here: List[Tuple[str, str]] = []
            for e, st in stats:
                n = e.name
                p = e.path
                if stat.S_ISLNK(st.st_mode):
                    if not os.path.exists(p):
                        self.broken.append((p, repo))
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if depth == 0 and (n.startswith(".") or p in self.skip_top):
                        continue
                    if n == ".git":
                        continue
                    kind = self._junk_kind(n, p, names)
                    if kind:
                        junk_here.append((kind, p))
                        continue
                    if n.endswith(PACKAGE_EXTS):
                        if n.endswith((".utm", ".pvm", ".vmwarevm", ".sparsebundle")):
                            sz = du(p)
                            if sz >= self.large_threshold:
                                self.large.append((sz, p))
                        continue
                    if st.st_mtime > newest:
                        newest = st.st_mtime
                    stack.append((p, repo, project, depth + 1))
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mtime > newest:
                    newest = st.st_mtime
                if n == ".DS_Store":
                    self.ds_store.append(p)
                    continue
                low = n.lower()
                if n.startswith("._") and n[2:] in names:
                    self.appledouble.append(p)
                    continue
                if n.startswith("~$") and low.endswith(OFFICE_EXTS) and NOW - st.st_mtime > DAY:
                    self.office_tmp.append(p)
                    continue
                if low.endswith(PARTIAL_EXTS) and NOW - st.st_mtime > 2 * DAY:
                    self.partial.append(p)
                    continue
                dataless = bool(getattr(st, "st_flags", 0) & SF_DATALESS)
                blocks = st.st_blocks * 512
                if dataless or blocks == 0:
                    continue
                if blocks >= self.large_threshold:
                    self.large.append((blocks, p))
                if st.st_size >= self.dupe_min and not repo and not project and not low.endswith(CODE_ARTIFACTS):
                    self.buckets[st.st_size].append(p)
            if junk_here:
                gi = os.path.join(d, ".git", "index")
                if os.path.exists(gi):
                    newest = max(newest, mtime(gi))
                stale = (NOW - newest) / DAY if newest else 9999.0
                for kind, p in junk_here:
                    self.junk.append((kind, p, d, stale))

    @staticmethod
    def _junk_kind(n: str, p: str, names: Set[str]) -> str:
        if n == "node_modules" and ("package.json" in names or "package-lock.json" in names):
            return "node_modules"
        if n == "__pycache__":
            return "pycache"
        if n in PY_TOOL_CACHES:
            return "pytool"
        if n in (".venv", "venv", "env", ".env", "virtualenv") and os.path.isfile(os.path.join(p, "pyvenv.cfg")):
            return "venv"
        if n == "target" and names & {"pom.xml", "Cargo.toml", "build.sbt"}:
            return "build"
        if n == "build" and names & (GRADLE_FILES | {"CMakeLists.txt"}):
            return "build"
        if n == ".gradle" and names & GRADLE_FILES:
            return "build"
        if n in JS_BUILD_DIRS and "package.json" in names:
            return "build"
        if n == ".tox" and names & {"tox.ini", "setup.py", "pyproject.toml"}:
            return "venv"
        return ""

    def dupes(self) -> List[List[str]]:
        if self._dupes is not None:
            return self._dupes
        groups: List[List[str]] = []
        for size, paths in self.buckets.items():
            if len(paths) < 2:
                continue
            uniq: Dict[Tuple[int, int], str] = {}
            for p in paths:
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                uniq.setdefault((st.st_dev, st.st_ino), p)  # hard links are not duplicates
            if len(uniq) < 2:
                continue
            by_part: Dict[str, List[str]] = defaultdict(list)
            for p in uniq.values():
                h = _partial_hash(p, size)
                if h:
                    by_part[h].append(p)
            for ps in by_part.values():
                if len(ps) < 2:
                    continue
                by_full: Dict[str, List[str]] = defaultdict(list)
                for p in ps:
                    h = _full_hash(p)
                    if h:
                        by_full[h].append(p)
                groups.extend(g for g in by_full.values() if len(g) > 1)
        self._dupes = groups
        return groups


def _partial_hash(p: str, size: int) -> str:
    try:
        h = hashlib.sha1()
        with open(p, "rb") as fh:
            h.update(fh.read(65536))
            if size > 131072:
                fh.seek(-65536, os.SEEK_END)
                h.update(fh.read(65536))
        return h.hexdigest()
    except OSError:
        return ""


def _full_hash(p: str) -> str:
    try:
        h = hashlib.sha1()
        with open(p, "rb") as fh:
            while True:
                b = fh.read(1 << 20)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except OSError:
        return ""


# =============================================================================
# Scan context
# =============================================================================


class Ctx:
    def __init__(self, opts):
        self.opts = opts
        self.ignore = load_ignore()
        self.run_bids, self.run_names = running_apps()
        self.run_norm = {alnum(n): n for n in self.run_names if alnum(n)}
        self.apps = AppIndex()
        self.fda = has_full_disk_access()
        self.claimed: List[str] = []
        self.warnings: List[str] = []
        self._walk: Optional[HomeWalk] = None

    def refresh_running(self):
        self.run_bids, self.run_names = running_apps()
        self.run_norm = {alnum(n): n for n in self.run_names if alnum(n)}

    def claim(self, *paths: str):
        for p in paths:
            if p:
                self.claimed.append(_n(p))

    def is_claimed(self, p: str) -> bool:
        p = _n(p)
        for cpath in self.claimed:
            if p == cpath or p.startswith(cpath + "/") or cpath.startswith(p + "/"):
                return True
        return False

    def pretty(self, ident: str) -> str:
        path = self.apps.bid_paths.get(ident.lower())
        return os.path.basename(path)[:-4] if path else ident

    def running(self, *idents: str) -> str:
        for ident in idents:
            if not ident:
                continue
            low = ident.lower()
            if low.startswith("group."):
                low = low[6:]
            if TEAM_RE.match(ident):
                low = low[11:]
            if low in self.run_bids or low in self.run_names:
                return self.pretty(low) if "." in low else ident
            if "." in low:
                for b in self.run_bids:
                    if b.startswith(low + "."):
                        return self.pretty(low)
                last = low.rsplit(".", 1)[-1]
                if len(last) >= 5 and last not in GENERIC_TOKENS and last in self.run_names:
                    return self.pretty(low)
            nm = alnum(ident)
            if len(nm) >= 3 and nm in self.run_norm:
                return self.pretty(ident)
        return ""

    def walk(self) -> HomeWalk:
        if self._walk is None:
            self._walk = HomeWalk(self.opts.large_mb, self.opts.dupe_mb)
        return self._walk


# =============================================================================
# Scanners
# =============================================================================

# ---------------------------------------------------------------- Trash


def scan_trash(ctx: Ctx) -> List[Finding]:
    out = []
    t = os.path.join(HOME, ".Trash")
    ctx.claim(t)
    count: Optional[int] = None
    size = 0
    try:
        count = len([n for n in os.listdir(t) if n not in (".DS_Store", ".localized")])
        size = du(t)
    except OSError:
        rc, o, _ = run(["osascript", "-e", 'tell application "Finder" to count items of trash'], 20)
        if rc == 0 and o.strip().isdigit():
            count = int(o.strip())
    vols = [v for v in sorted(glob.glob("/Volumes/*/.Trashes/%d" % UID)) if du(v) > 0]
    vsz = sum(du(v) for v in vols)
    if (count or 0) > 0 or vsz > 0:
        desc = ("%d item(s) in your Trash" % count) if count is not None else "Items in your Trash"
        if vols:
            desc += " + Trash folders on %d external volume(s)" % len(vols)
        out.append(mk("trash", "Empty the Trash", REC, desc + " — you already chose to delete these.",
                      paths=[t] + vols, size=size + vsz, action=ACT_EMPTY_TRASH, keep_zero=True,
                      impact="Permanent: items in the Trash cannot be recovered afterwards."))
    return out

# ---------------------------------------------------------------- Snapshots


def scan_snapshots(ctx: Ctx) -> List[Finding]:
    rc, out, err = run(["tmutil", "listlocalsnapshots", "/"], 30)
    snaps = [l.strip() for l in out.splitlines()
             if l.strip() and not l.lower().startswith("snapshots for")]
    if not snaps:
        return []
    return [mk("snapshots", "Thin Time Machine local snapshots (%d)" % len(snaps), REV,
               "Local snapshots (%s) keep copies of deleted/changed files and show up as "
               "'purgeable' space. macOS removes them when it needs room, but you can free the "
               "space right now." % ", ".join(snaps[:3]) + (" …" if len(snaps) > 3 else ""),
               size=0, action=ACT_CMD, keep_zero=True, sudo=True,
               cmds=[["tmutil", "thinlocalsnapshots", "/", "999999999999", "4"]],
               impact="You lose the ability to restore from these local snapshots; "
                      "backups on your Time Machine disk are not affected.")]

# ---------------------------------------------------------------- Browsers


CHROMIUM_BROWSERS = [
    # display name, Application Support rel, Caches rel, bundle id, app names
    ("Google Chrome", "Google/Chrome", "Google/Chrome", "com.google.Chrome", ["Google Chrome.app"]),
    ("Chrome Beta", "Google/Chrome Beta", "Google/Chrome Beta", "com.google.Chrome.beta", ["Google Chrome Beta.app"]),
    ("Chrome Canary", "Google/Chrome Canary", "Google/Chrome Canary", "com.google.Chrome.canary", ["Google Chrome Canary.app"]),
    ("Chromium", "Chromium", "Chromium", "org.chromium.Chromium", ["Chromium.app"]),
    ("Brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser", "com.brave.Browser", ["Brave Browser.app"]),
    ("Brave Beta", "BraveSoftware/Brave-Browser-Beta", "BraveSoftware/Brave-Browser-Beta", "com.brave.Browser.beta", ["Brave Browser Beta.app"]),
    ("Brave Nightly", "BraveSoftware/Brave-Browser-Nightly", "BraveSoftware/Brave-Browser-Nightly", "com.brave.Browser.nightly", ["Brave Browser Nightly.app"]),
    ("Microsoft Edge", "Microsoft Edge", "Microsoft Edge", "com.microsoft.edgemac", ["Microsoft Edge.app"]),
    ("Vivaldi", "Vivaldi", "Vivaldi", "com.vivaldi.Vivaldi", ["Vivaldi.app"]),
    ("Opera", "com.operasoftware.Opera", "com.operasoftware.Opera", "com.operasoftware.Opera", ["Opera.app"]),
    ("Opera GX", "com.operasoftware.OperaGX", "com.operasoftware.OperaGX", "com.operasoftware.OperaGX", ["Opera GX.app"]),
    ("Arc", "Arc/User Data", "Arc", "company.thebrowser.Browser", ["Arc.app"]),
    ("Dia", "Dia/User Data", "Dia", "company.thebrowser.dia", ["Dia.app"]),
    ("Comet", "Comet", "Comet", "ai.perplexity.comet", ["Comet.app"]),
    ("ChatGPT Atlas", "com.openai.atlas", "com.openai.atlas", "com.openai.atlas", ["ChatGPT Atlas.app"]),
]
CHROMIUM_PROFILE_CACHES = ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache",
                           "DawnWebGPUCache", "GraphiteDawnCache", "GrShaderCache", "ShaderCache",
                           "Service Worker/CacheStorage", "Service Worker/ScriptCache",
                           "Application Cache", "Media Cache"]
CHROMIUM_ROOT_CACHES = ["GrShaderCache", "ShaderCache", "GraphiteDawnCache", "component_crx_cache",
                        "extensions_crx_cache", "Crashpad/completed", "Crashpad/pending",
                        "BrowserMetrics", "Snapshots", "SwReporter", "Webstore Downloads"]
CHROMIUM_AI = ["OptGuideOnDeviceModel", "optimization_guide_model_store", "OnDeviceHeadSuggestModel",
               "screen_ai", "OptGuideOnDeviceClassifierModel"]
FIREFOX_LIKE = [
    ("Firefox", "Firefox", "Firefox", "org.mozilla.firefox", ["Firefox.app", "Firefox Developer Edition.app", "Firefox Nightly.app"]),
    ("Zen", "zen", "zen", "app.zen-browser.zen", ["Zen.app", "Zen Browser.app"]),
    ("LibreWolf", "librewolf", "librewolf", "io.gitlab.librewolf-community", ["LibreWolf.app"]),
    ("Waterfox", "Waterfox", "Waterfox", "net.waterfox.waterfox", ["Waterfox.app"]),
]
FIREFOX_PROFILE_CACHES = ["cache2", "startupCache", "shader-cache", "OfflineCache", "thumbnails",
                          "crashes", "minidumps", "datareporting/archived", "saved-telemetry-pings"]


def _app_installed(ctx: Ctx, bid: str, apps: List[str]) -> bool:
    if ctx.apps.has_bid(bid):
        return True
    for r in ("/Applications", os.path.join(HOME, "Applications")):
        for a in apps:
            if os.path.exists(os.path.join(r, a)):
                return True
    return False


def scan_browsers(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    after_cache = "Sites load a little slower the first time. Logins, history, bookmarks and passwords are NOT touched."
    for name, sup_rel, cache_rel, bid, apps in CHROMIUM_BROWSERS:
        sup = os.path.join(AS, sup_rel)
        cache = os.path.join(CACHES, cache_rel)
        if not (isdir(sup) or isdir(cache)):
            continue
        ctx.claim(sup, cache)
        if not _app_installed(ctx, bid, apps):
            paths = [p for p in (sup, cache) if os.path.lexists(p)]
            out.append(mk("browsers", "%s — leftover profile (browser not installed)" % name, REV,
                          "%s is not installed, but its whole profile is still here: bookmarks, "
                          "history, saved passwords, extensions and cache." % name,
                          paths=paths, action=ACT_TRASH, location=sup,
                          impact="Moved to Trash. Export bookmarks/passwords first if you may use it again."))
            continue
        cpaths: List[str] = []
        if isdir(cache):
            cpaths += children(cache)
        for prof in listdir(sup):
            pp = os.path.join(sup, prof)
            if not isdir(pp) or not (os.path.isfile(os.path.join(pp, "Preferences"))
                                     or prof == "Default" or prof.startswith("Profile ")):
                continue
            for sub in CHROMIUM_PROFILE_CACHES:
                cpaths += children(os.path.join(pp, sub))
        for sub in CHROMIUM_ROOT_CACHES:
            p = os.path.join(sup, sub)
            if isdir(p):
                cpaths += children(p)
        if cpaths:
            out.append(mk("browsers", "%s — browsing cache" % name, REC,
                          "Temporary copies of websites, scripts, images and GPU shaders, crash "
                          "dumps and update leftovers. Rebuilt automatically as you browse.",
                          paths=cpaths, location=sup, owners=[bid, name], impact=after_cache))
        mpaths = [os.path.join(sup, m) for m in CHROMIUM_AI if os.path.exists(os.path.join(sup, m))]
        if mpaths:
            out.append(mk("browsers", "%s — on-device AI / optimization models" % name, REV,
                          "Machine-learning models downloaded by the browser (e.g. Gemini Nano, "
                          "page-optimisation hints). Downloaded again only if a feature needs them.",
                          paths=mpaths, location=sup, owners=[bid, name]))
    for name, sup_rel, cache_rel, bid, apps in FIREFOX_LIKE:
        sup = os.path.join(AS, sup_rel)
        cache = os.path.join(CACHES, cache_rel)
        if not (isdir(sup) or isdir(cache)):
            continue
        ctx.claim(sup, cache)
        if not _app_installed(ctx, bid, apps):
            out.append(mk("browsers", "%s — leftover profile (browser not installed)" % name, REV,
                          "%s is not installed, but its profile (bookmarks, history, passwords) "
                          "and cache are still here." % name,
                          paths=[p for p in (sup, cache) if os.path.lexists(p)], action=ACT_TRASH,
                          location=sup, impact="Moved to Trash."))
            continue
        cpaths = []
        for base in (os.path.join(sup, "Profiles"), os.path.join(cache, "Profiles")):
            for prof in listdir(base):
                for sub in FIREFOX_PROFILE_CACHES:
                    cpaths += children(os.path.join(base, prof, sub))
        cpaths += children(os.path.join(sup, "Crash Reports"), exclude=("InstallTime", "events"))
        if cpaths:
            out.append(mk("browsers", "%s — browsing cache & crash reports" % name, REC,
                          "Web cache, startup/shader caches, thumbnails and crash reports.",
                          paths=cpaths, location=sup, owners=[bid, name], impact=after_cache))
    # Safari (needs Full Disk Access for some folders)
    saf_dirs = [os.path.join(CACHES, "com.apple.Safari"),
                os.path.join(LIB, "Containers", "com.apple.Safari", "Data", "Library", "Caches"),
                os.path.join(LIB, "Containers", "com.apple.Safari.WebApp", "Data", "Library", "Caches")]
    spaths = []
    for d in saf_dirs:
        ctx.claim(d)
        spaths += children(d)
    if spaths:
        out.append(mk("browsers", "Safari — browsing cache (incl. Web Apps)", REC,
                      "Safari's and Safari Web Apps' cached pages, images and scripts.",
                      paths=spaths, location=saf_dirs[1], owners=["com.apple.Safari", "Safari"],
                      impact=after_cache))
    return out

# ---------------------------------------------------------------- Code editors


EDITORS = [
    # display, Application Support folder, dot folder, bundle id
    ("VS Code", "Code", ".vscode", "com.microsoft.VSCode"),
    ("VS Code Insiders", "Code - Insiders", ".vscode-insiders", "com.microsoft.VSCodeInsiders"),
    ("VSCodium", "VSCodium", ".vscode-oss", "com.vscodium"),
    ("Cursor", "Cursor", ".cursor", "com.todesktop.230313mzl4w4u92"),
    ("Windsurf", "Windsurf", ".windsurf", "com.exafunction.windsurf"),
    ("Antigravity", "Antigravity", ".antigravity", "com.google.antigravity"),
    ("Kiro", "Kiro", ".kiro", "dev.kiro.desktop"),
    ("Trae", "Trae", ".trae", "com.trae.app"),
]
EDITOR_CACHES = ["Cache", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache",
                 "GraphiteDawnCache", "GrShaderCache", "ShaderCache", "CachedProfilesData",
                 "Service Worker/CacheStorage", "Service Worker/ScriptCache", "Crashpad/completed",
                 "Crashpad/pending"]


def _ext_manifest(extdir: str) -> Tuple[Optional[Set[str]], Set[str]]:
    data = read_json(os.path.join(extdir, "extensions.json"))
    if not isinstance(data, list) or not data:
        return None, set()
    dirs: Set[str] = set()
    ids: Set[str] = set()
    for e in data:
        if not isinstance(e, dict):
            continue
        ident = (e.get("identifier") or {}).get("id")
        if ident:
            ids.add(str(ident).lower())
        rel = e.get("relativeLocation")
        if not rel:
            loc = e.get("location")
            if isinstance(loc, dict):
                rel = os.path.basename(str(loc.get("path") or loc.get("fsPath") or "").rstrip("/"))
            elif isinstance(loc, str):
                rel = os.path.basename(loc.rstrip("/"))
        if rel:
            dirs.add(str(rel))
    return (dirs or None), ids


def _builtin_ext_ids(ctx: Ctx, bid: str) -> Set[str]:
    path = ctx.apps.bid_paths.get(bid.lower())
    out: Set[str] = set()
    if not path:
        return out
    base = os.path.join(path, "Contents", "Resources", "app", "extensions")
    for n in listdir(base):
        pj = read_json(os.path.join(base, n, "package.json"))
        if isinstance(pj, dict) and pj.get("name"):
            out.add(("%s.%s" % (pj.get("publisher", "vscode"), pj["name"])).lower())
    return out


def scan_editors(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    for name, sup_name, dot, bid in EDITORS:
        sup = os.path.join(AS, sup_name)
        extdir = os.path.join(HOME, dot, "extensions")
        if not isdir(sup) and not isdir(extdir):
            continue
        ctx.claim(sup)
        owners = [bid, sup_name, name]
        vsix = os.path.join(sup, "CachedExtensionVSIXs")
        if isdir(vsix):
            out.append(mk("editors", "%s — cached extension installers (VSIX)" % name, REC,
                          "A copy of every extension package %s downloaded. The extensions are "
                          "already installed; these copies are only used to re-install." % name,
                          paths=children(vsix), location=vsix, owners=owners,
                          impact="Re-installing an extension downloads it again."))
        cp: List[str] = []
        for sub in EDITOR_CACHES:
            cp += children(os.path.join(sup, sub))
        cp += children(os.path.join(sup, "logs"), min_age_days=1)
        if cp:
            out.append(mk("editors", "%s — caches, crash dumps & old logs" % name, REC,
                          "Chromium/Electron caches and old session logs of the editor.",
                          paths=cp, location=sup, owners=owners,
                          impact="Rebuilt automatically; nothing about your settings changes."))
        cd = os.path.join(sup, "CachedData")
        builds = sorted([p for p in children(cd) if isdir(p)], key=mtime, reverse=True)
        if len(builds) > 1:
            out.append(mk("editors", "%s — engine caches of previous versions" % name, REC,
                          "Compiled-code caches for %d older %s releases (newest is kept)."
                          % (len(builds) - 1, name), paths=builds[1:], location=cd, owners=owners))
        ws = os.path.join(sup, "User", "workspaceStorage")
        orphans = []
        for d in children(ws):
            data = read_json(os.path.join(d, "workspace.json"))
            if not isinstance(data, dict):
                continue
            uri = data.get("folder") or data.get("workspace")
            if not isinstance(uri, str) or not uri.startswith("file://"):
                continue
            path = urllib.parse.unquote(urllib.parse.urlparse(uri).path)
            if path and not os.path.exists(path):
                orphans.append(d)
        if orphans:
            out.append(mk("editors", "%s — state of %d deleted/moved projects" % (name, len(orphans)), REC,
                          "Workspace state (open tabs, search history, extension data) for project "
                          "folders that no longer exist on disk.", paths=orphans, location=ws, owners=owners))
        installed_ids: Set[str] = set()
        if isdir(extdir):
            dirs, installed_ids = _ext_manifest(extdir)
            obsolete = read_json(os.path.join(extdir, ".obsolete"))
            obsolete = obsolete if isinstance(obsolete, dict) else {}
            left = []
            entries = [n for n in listdir(extdir) if not n.startswith(".") and isdir(os.path.join(extdir, n))]
            if dirs is not None:
                left = [n for n in entries if n not in dirs or n in obsolete]
            else:
                groups: Dict[str, List[str]] = defaultdict(list)
                for n in entries:
                    m = re.match(r"^(.+?)-(\d+\.\d+\.\d+[^/]*)$", n)
                    if m:
                        plat = re.sub(r"^[\d.]+", "", m.group(2))
                        groups[m.group(1) + plat].append(n)
                for g in groups.values():
                    if len(g) > 1:
                        g.sort(key=parse_version, reverse=True)
                        left += g[1:]
                left += [n for n in entries if n in obsolete and n not in left]
            lp = [os.path.join(extdir, n) for n in left if age_days(os.path.join(extdir, n)) >= 1]
            if lp:
                out.append(mk("editors", "%s — old / uninstalled extension versions (%d)" % (name, len(lp)), REC,
                              "Extension folders that %s no longer uses (replaced by newer versions or "
                              "uninstalled)." % name, paths=lp, location=extdir, owners=owners))
        if installed_ids:
            builtin = _builtin_ext_ids(ctx, bid)
            gs = os.path.join(sup, "User", "globalStorage")
            for d in children(gs):
                n = os.path.basename(d).lower()
                if not isdir(d) or "." not in n or n in installed_ids or n in builtin:
                    continue
                if n.startswith(("vscode.", "ms-vscode.", "github.copilot")):
                    continue
                if du(d) < 200_000:
                    continue
                out.append(mk("editors", "%s — data of removed extension '%s'" % (name, os.path.basename(d)), REV,
                              "Saved data of an extension that is no longer installed (may contain "
                              "its history, e.g. AI chat tasks).", paths=[d], owners=owners))
    return out

# ---------------------------------------------------------------- Xcode


def scan_xcode(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    dev = os.path.join(LIB, "Developer")
    xc = os.path.join(dev, "Xcode")
    ctx.claim(dev, os.path.join(CACHES, "com.apple.dt.Xcode"))
    xcode_apps = glob.glob("/Applications/Xcode*.app")
    owners = ["com.apple.dt.Xcode", "Xcode", "Simulator"]
    if not isdir(dev):
        return out
    if not xcode_apps and isdir(xc):
        out.append(mk("xcode", "Xcode data (Xcode is not installed)", REV,
                      "DerivedData, archives, device support and caches from an Xcode that is no "
                      "longer installed.", paths=[xc], action=ACT_TRASH))
    else:
        dd = os.path.join(xc, "DerivedData")
        if isdir(dd):
            out.append(mk("xcode", "Xcode DerivedData", REC,
                          "Intermediate build products and indexes. Xcode rebuilds them.",
                          paths=children(dd), location=dd, owners=owners,
                          impact="Next build of each project is a full (slower) build."))
        for plat in ("iOS", "watchOS", "tvOS", "visionOS", "xrOS", "macOS"):
            ds = os.path.join(xc, "%s DeviceSupport" % plat)
            vers = [p for p in children(ds) if isdir(p)]
            if len(vers) > 1:
                vers.sort(key=lambda p: parse_version(os.path.basename(p)), reverse=True)
                out.append(mk("xcode", "%s DeviceSupport — %d old versions" % (plat, len(vers) - 1), REC,
                              "Debug symbols copied from devices running older %s versions; the "
                              "newest is kept and old ones are re-copied if you connect such a device."
                              % plat, paths=vers[1:], location=ds))
        for rel, title, why in (("UserData/Previews", "SwiftUI preview caches", "Rebuilt when you open a preview."),
                                ("Products", "Xcode Products cache", "Built products cache; regenerated on build."),
                                ("UserData/IB Support", "Interface Builder caches", "Regenerated automatically.")):
            p = os.path.join(xc, rel)
            if isdir(p):
                out.append(mk("xcode", title, REC, why, paths=children(p), location=p, owners=owners))
        arch = os.path.join(xc, "Archives")
        if isdir(arch):
            out.append(mk("xcode", "Xcode Archives", REV,
                          "Archived app builds. Needed to re-upload a build or symbolicate crash "
                          "reports of released versions.", paths=children(arch), location=arch,
                          action=ACT_TRASH))
    sc = os.path.join(CACHES, "com.apple.dt.Xcode")
    if isdir(sc):
        out.append(mk("xcode", "Xcode app cache", REC, "Download & documentation caches.",
                      paths=children(sc), location=sc, owners=owners))
    csc = os.path.join(dev, "CoreSimulator", "Caches")
    if isdir(csc):
        out.append(mk("xcode", "Simulator caches", REC, "dyld and runtime caches for simulators.",
                      paths=children(csc), location=csc, owners=owners))
    devices = os.path.join(dev, "CoreSimulator", "Devices")
    if xcode_apps and shutil.which("xcrun"):
        rc, o, _ = run(["xcrun", "simctl", "list", "devices", "unavailable"], 60)
        n = len(re.findall(r"\(unavailable", o))
        if n:
            out.append(mk("xcode", "Delete %d unavailable simulators" % n, REC,
                          "Simulators whose runtime is no longer installed — they can never run again.",
                          size=0, action=ACT_CMD, keep_zero=True,
                          cmds=[["xcrun", "simctl", "delete", "unavailable"]]))
    if isdir(devices) and du(devices) > 500e6:
        out.append(mk("xcode", "Simulator devices (all)", KEEP,
                      "All simulator devices and their app data. Erase individual ones in Xcode ▸ "
                      "Devices & Simulators.", paths=[devices], action=ACT_NONE))
    return out

# ---------------------------------------------------------------- Docker / Colima


def _docker_df() -> Dict[str, Tuple[int, int]]:
    rc, out, _ = run(user_cmd(["docker", "system", "df", "--format", "{{.Type}}|{{.Size}}|{{.Reclaimable}}"]), 90)
    res: Dict[str, Tuple[int, int]] = {}
    if rc != 0:
        return res
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) == 3:
            res[parts[0].strip().lower()] = (parse_size(parts[1]), parse_size(parts[2]))
    return res


def scan_docker(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    colima = os.path.join(HOME, ".colima")
    ctx.claim(colima, os.path.join(HOME, ".docker"))
    if shutil.which("docker"):
        rc, o, e = run(user_cmd(["docker", "info", "--format", "{{.ServerVersion}}"]), 20)
        if rc == 0 and o.strip():
            df = _docker_df()
            cont = df.get("containers", (0, 0))[1]
            build = df.get("build cache", (0, 0))[1]
            imgs = df.get("images", (0, 0))[1]
            vols = df.get("local volumes", (0, 0))[1]
            out.append(mk("docker", "Docker: stopped containers, dangling images, unused networks", REC,
                          "Leftovers of finished containers and untagged image layers.",
                          size=cont, action=ACT_CMD, keep_zero=True,
                          cmds=[user_cmd(["docker", "system", "prune", "-f"])],
                          impact="Stopped containers are removed (their writable layer is lost)."))
            if build:
                out.append(mk("docker", "Docker: build cache", REC,
                              "Cached build layers; rebuilt on the next docker build.", size=build,
                              action=ACT_CMD, cmds=[user_cmd(["docker", "builder", "prune", "-af"])],
                              impact="Next image builds take longer."))
            if imgs:
                out.append(mk("docker", "Docker: images not used by any container", REV,
                              "Tagged images no container uses. Pulled/built again when needed.",
                              size=imgs, action=ACT_CMD, cmds=[user_cmd(["docker", "image", "prune", "-af"])]))
            if vols:
                _, h, _ = run(user_cmd(["docker", "volume", "prune", "--help"]), 20)
                cmd = ["docker", "volume", "prune", "-f"] + (["-a"] if "--all" in h else [])
                out.append(mk("docker", "Docker: volumes not attached to a container", REV,
                              "Named/anonymous volumes no container uses. ⚠ Volumes hold DATA "
                              "(databases etc.).", size=vols, action=ACT_CMD, cmds=[user_cmd(cmd)],
                              impact="Data inside these volumes is permanently lost."))
            if isdir(colima):
                out.append(mk("docker", "Colima: give freed VM space back to macOS (fstrim)", REC,
                              "After pruning, the VM disk keeps its size until it is trimmed.",
                              size=0, action=ACT_CMD, keep_zero=True,
                              cmds=[user_cmd(["colima", "ssh", "--", "sudo", "fstrim", "-av"])]))
        elif isdir(colima):
            out.append(mk("docker", "Docker engine (Colima) is not running", KEEP,
                          "Start it with `colima start` and re-scan to analyse images, containers, "
                          "volumes and build cache.", size=0, action=ACT_NONE, keep_zero=True))
    if isdir(colima):
        out.append(mk("docker", "Colima VM disk (all Docker data)", KEEP,
                      "Virtual machine holding every Docker image, container and volume. Prune "
                      "inside Docker instead; delete the VM only if you no longer use Docker.",
                      paths=[colima], location=colima, action=ACT_CMD,
                      cmds=[user_cmd(["colima", "delete", "--force"])],
                      impact="Deletes the whole VM including all images, containers and volumes."))
        logs = [p for p in glob.glob(os.path.join(colima, "**", "*.log"), recursive=True)
                if du(p) > 1e6 and age_days(p) > 1]
        if logs:
            out.append(mk("docker", "Colima / Lima logs", REC, "VM log files.", paths=logs, location=colima))
    dd = os.path.join(LIB, "Containers", "com.docker.docker")
    if isdir(dd):
        ctx.claim(dd)
        raw = os.path.join(dd, "Data", "vms", "0", "data", "Docker.raw")
        if os.path.exists(raw):
            out.append(mk("docker", "Docker Desktop disk image", KEEP,
                          "Docker Desktop's VM disk. Use Docker Desktop ▸ Troubleshoot ▸ Clean/Purge.",
                          paths=[raw], action=ACT_NONE))
    return out

# ---------------------------------------------------------------- Developer tools


def _keep_newest_versions(parent: str, keep: int = 1, pattern=None) -> List[str]:
    vers = [p for p in children(parent) if isdir(p) and (pattern is None or re.match(pattern, os.path.basename(p)))]
    if len(vers) <= keep:
        return []
    vers.sort(key=lambda p: (parse_version(os.path.basename(p)), mtime(p)), reverse=True)
    return vers[keep:]


def scan_dev(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    H = HOME
    j = os.path.join

    def add(title, paths, rec, reason, impact="", owners=None, action=ACT_DELETE, min_size=100_000,
            cmds=None, size=None):
        paths = [p for p in paths if os.path.lexists(p) and not ctx.is_claimed(p)]
        if not paths and not cmds:
            return
        if cmds:
            f = mk("dev", title, rec, reason, size=size or 0, impact=impact, owners=owners or [],
                   action=ACT_CMD, cmds=cmds, keep_zero=True)
            out.append(f)
            return
        f = mk("dev", title, rec, reason, paths=paths, impact=impact, owners=owners or [], action=action)
        for p in paths:
            ctx.claim(p)
        if f.size >= min_size:
            out.append(f)

    redl = "Downloaded again automatically when a project needs it."
    # JavaScript
    add("npm cache", [j(H, ".npm", "_cacache")], REC, "Downloaded npm package tarballs.", redl)
    add("npm logs", [j(H, ".npm", "_logs")], REC, "Debug logs from npm runs.")
    add("npx cache", [j(H, ".npm", "_npx")], REC, "Packages fetched by npx.", redl)
    add("Yarn cache", [j(CACHES, "Yarn"), j(H, ".yarn", "berry", "cache"), j(H, ".cache", "yarn")], REC,
        "Downloaded Yarn packages.", redl)
    pnpm_store = [p for p in (j(LIB, "pnpm", "store"), j(H, ".pnpm-store"), j(H, ".local", "share", "pnpm", "store")) if isdir(p)]
    if pnpm_store and shutil.which("pnpm"):
        add("pnpm store — unreferenced packages", [], REC, "Packages no project references any more.",
            cmds=[user_cmd(["pnpm", "store", "prune"])])
        ctx.claim(*pnpm_store)
    elif pnpm_store:
        add("pnpm store", pnpm_store, REV, "Content-addressed package store.", redl)
    add("Bun cache", [j(H, ".bun", "install", "cache")], REC, "Downloaded Bun packages.", redl)
    add("Deno cache", [j(CACHES, "deno")], REC, "Downloaded Deno modules.", redl)
    add("node-gyp / Electron / TypeScript caches",
        [j(CACHES, "node-gyp"), j(CACHES, "electron"), j(CACHES, "electron-builder"), j(CACHES, "typescript"),
         j(H, ".electron-gyp")], REC, "Downloaded headers and binaries for native builds.", redl)
    add("NVM download cache", [j(H, ".nvm", ".cache")], REC, "Node.js installer tarballs already installed.")
    # Python
    add("pip cache", [j(CACHES, "pip"), j(H, ".cache", "pip")], REC, "Downloaded Python wheels.", redl)
    add("pipenv cache", [j(CACHES, "pipenv")], REC, "Downloaded packages for pipenv.", redl)
    add("Poetry cache", [j(CACHES, "pypoetry", "cache"), j(CACHES, "pypoetry", "artifacts")], REC,
        "Downloaded packages for Poetry.", redl)
    add("Poetry virtualenvs", [j(CACHES, "pypoetry", "virtualenvs")], REV,
        "Virtual environments Poetry created for your projects.", "Recreate with `poetry install`.")
    add("uv cache", [j(H, ".cache", "uv"), j(CACHES, "uv")], REC, "uv's package cache.", redl)
    if shutil.which("conda"):
        add("Conda package cache & tarballs", [], REC, "Unused package tarballs and caches.",
            cmds=[user_cmd(["conda", "clean", "--all", "-y"])])
    # Go / Rust / others
    if shutil.which("go"):
        if isdir(j(CACHES, "go-build")):
            add("Go build cache", [], REC, "Compiled Go packages.", cmds=[user_cmd(["go", "clean", "-cache"])],
                size=du(j(CACHES, "go-build")))
            ctx.claim(j(CACHES, "go-build"))
    else:
        add("Go build cache", [j(CACHES, "go-build")], REC, "Compiled Go packages.")
    add("Go module cache", [j(H, "go", "pkg", "mod")], REV, "Downloaded Go modules.", redl)
    add("Cargo registry & git caches", [j(H, ".cargo", "registry", "cache"), j(H, ".cargo", "registry", "src"),
                                        j(H, ".cargo", "git", "checkouts")], REC,
        "Downloaded/extracted crates.", redl)
    add("CocoaPods / Carthage caches", [j(CACHES, "CocoaPods"), j(CACHES, "org.carthage.CarthageKit")], REC,
        "Downloaded pods/frameworks.", redl)
    add("Composer cache", [j(H, ".composer", "cache"), j(CACHES, "composer")], REC, "Downloaded PHP packages.", redl)
    add("pre-commit cache", [j(H, ".cache", "pre-commit")], REC, "Hook environments; rebuilt on next run.")
    # Java
    m2 = j(H, ".m2", "repository")
    if isdir(m2):
        lu = glob.glob(j(m2, "**", "*.lastUpdated"), recursive=True)
        add("Maven failed-download markers (*.lastUpdated)", lu, REC,
            "Markers of failed downloads that can block re-download.", min_size=1)
        add("Maven local repository", [m2], REV, "All downloaded Java dependencies.",
            "Downloaded again on the next build (needs internet; can take a while).")
    add("Maven wrapper — old distributions", _keep_newest_versions(j(H, ".m2", "wrapper", "dists")), REC,
        "Older Maven versions downloaded by mvnw.")
    g = j(H, ".gradle")
    add("Gradle wrapper — old distributions", _keep_newest_versions(j(g, "wrapper", "dists")), REC,
        "Older Gradle versions downloaded by gradlew (newest kept).")
    add("Gradle — caches of old Gradle versions", _keep_newest_versions(j(g, "caches"), pattern=r"^\d+\.\d+"), REC,
        "Per-version caches of Gradle releases you no longer use.")
    add("Gradle build cache", [j(g, "caches", "build-cache-1")], REC, "Cached task outputs.", "Next build is slower.")
    add("Gradle daemon logs (old versions)", _keep_newest_versions(j(g, "daemon")), REC, "Logs of old Gradle daemons.")
    add("Gradle dependency cache", [j(g, "caches", "modules-2")], REV, "Downloaded dependencies.", redl)
    # Android / Flutter
    add("Android build caches", [j(H, ".android", "cache"), j(H, ".android", "build-cache")], REC, "Build caches.")
    add("Android emulator images (AVDs)", [j(H, ".android", "avd")], REV, "Virtual devices you created.")
    add("Android SDK system images", [j(LIB, "Android", "sdk", "system-images")], REV,
        "Emulator OS images; re-download in SDK Manager.")
    add("Dart/Flutter pub cache", [j(H, ".pub-cache")], REV, "Downloaded Dart packages.", redl)
    # Browsers for testing / AI models
    add("Playwright / Puppeteer / Selenium browsers",
        [j(CACHES, "ms-playwright"), j(H, ".cache", "ms-playwright"), j(H, ".cache", "puppeteer"),
         j(H, ".cache", "selenium")], REV, "Test-automation browsers.", "Re-installed by the test tool when needed.")
    add("AI models (Hugging Face, PyTorch, Whisper, LM Studio, Ollama)",
        [j(H, ".cache", "huggingface"), j(H, ".cache", "torch"), j(H, ".cache", "whisper"),
         j(H, ".cache", "lm-studio"), j(H, ".lmstudio", "models"), j(H, ".ollama", "models")], REV,
        "Downloaded machine-learning models — often several GB.", "Downloaded again when a model is used.")
    # Version managers
    nvm = j(H, ".nvm", "versions", "node")
    if isdir(nvm):
        keep: Set[str] = set()
        nb = shutil.which("node")
        if nb and under(os.path.realpath(nb), nvm):
            keep.add(os.path.realpath(nb)[len(nvm) + 1:].split("/")[0])
        try:
            alias = open(j(H, ".nvm", "alias", "default")).read().strip()
        except OSError:
            alias = ""
        vers = sorted([os.path.basename(p) for p in children(nvm) if isdir(p)], key=parse_version, reverse=True)
        if vers:
            keep.add(vers[0])
        if alias:
            a = alias.lstrip("v")
            for v in vers:
                if v.lstrip("v") == a or v.lstrip("v").startswith(a + "."):
                    keep.add(v)
                    break
        add("NVM — inactive Node.js versions", [j(nvm, v) for v in vers if v not in keep], REV,
            "Node.js versions that are neither active, default nor newest (%s kept)." % ", ".join(sorted(keep)),
            "Reinstall with `nvm install <version>` if a project needs it.")
    pyenv = j(H, ".pyenv", "versions")
    if isdir(pyenv):
        try:
            cur = {x.strip() for x in open(j(H, ".pyenv", "version")).read().split()}
        except OSError:
            cur = set()
        add("pyenv — Python versions not set as global", [p for p in children(pyenv) if os.path.basename(p) not in cur],
            REV, "Python versions installed with pyenv but not your global version.",
            "Projects with a .python-version file may need them.")
    sdk = j(H, ".sdkman")
    if isdir(sdk):
        add("SDKMAN archives & temp", [j(sdk, "archives"), j(sdk, "tmp")], REC, "Downloaded SDK zips already installed.")
        olds = []
        for cand in children(j(sdk, "candidates")):
            curl = j(cand, "current")
            tgt = os.path.realpath(curl) if os.path.islink(curl) else ""
            for v in children(cand):
                if isdir(v) and os.path.basename(v) != "current" and os.path.realpath(v) != tgt:
                    olds.append(v)
        add("SDKMAN — non-current SDK versions", olds, REV, "SDK versions installed but not set as current.")
    # JetBrains current version caches
    jbc = j(CACHES, "JetBrains")
    cur_jb = []
    groups: Dict[str, List[str]] = defaultdict(list)
    for p in children(jbc):
        m = re.match(r"^([A-Za-z]+?)(\d{4}\.\d+)$", os.path.basename(p))
        if m:
            groups[m.group(1)].append(p)
    for prod, ps in groups.items():
        ps.sort(key=lambda p: parse_version(os.path.basename(p)), reverse=True)
        cur_jb.append(ps[0])
    if cur_jb:
        add("JetBrains IDE caches & indexes (current version)", cur_jb, REV,
            "Project indexes and compiler caches — same as File ▸ Invalidate Caches.",
            "First start afterwards re-indexes your projects (slow for a few minutes).",
            owners=["com.jetbrains.intellij", "idea", "IntelliJ IDEA", "pycharm", "webstorm", "goland", "clion"])
    # Jenkins
    jen = j(H, ".jenkins")
    if isdir(jen):
        jrunning = run(["pgrep", "-f", "jenkins"], 10)[0] == 0
        add("Jenkins plugin backups (*.bak)", glob.glob(j(jen, "plugins", "*.bak")), REC,
            "Previous plugin versions kept only to allow a downgrade.")
        add("Jenkins update-center cache", [j(jen, "updates")], REC, "Plugin metadata; re-downloaded by Jenkins.")
        add("Jenkins caches", [j(jen, "caches")], REC, "Git/SCM caches; rebuilt by the next build.")
        add("Jenkins rotated logs", [p for p in glob.glob(j(jen, "logs", "**", "*"), recursive=True)
                                     if re.search(r"\.log\.\d+$", p) and os.path.isfile(p)], REC, "Old rotated logs.")
        add("Jenkins job workspaces", [j(jen, "workspace")], REV,
            "Checked-out sources & build outputs; recreated by the next build of each job.",
            owners=["jenkins"] if jrunning else [])
        if jrunning and out and out[-1].title == "Jenkins job workspaces":
            out[-1].running = "Jenkins"
    # AI / CLI tools
    add("SonarLint/SonarQube for IDE storage", [j(H, ".sonarlint", "storage")], REV,
        "Rules & issues synced from SonarQube/SonarCloud; re-synced when connected mode is used.")
    add("Codex CLI cache & logs", [j(H, ".codex", "cache"), j(H, ".codex", "log")]
        + children(j(H, ".codex", "tmp"), min_age_days=1), REC,
        "Caches, debug logs and temp files of the Codex CLI (sessions/history are kept).",
        owners=["codex"])
    add("Gemini CLI temp / checkpoint data", [j(H, ".gemini", "tmp")], REV,
        "Gemini CLI's per-project temp data (may include saved chats/checkpoints).", owners=["gemini"])
    # Generic XDG cache
    xdg = j(H, ".cache")
    model_names = {"huggingface", "torch", "whisper", "lm-studio", "puppeteer", "ms-playwright", "selenium",
                   "pip", "uv", "yarn", "pre-commit"}
    rest = []
    for p in children(xdg):
        if os.path.basename(p) in model_names or ctx.is_claimed(p):
            continue
        if du(p) >= 1e6:
            add("~/.cache: %s" % os.path.basename(p), [p], REC,
                "Tool cache in the standard ~/.cache folder; recreated when needed.",
                owners=[os.path.basename(p)])
        else:
            rest.append(p)
    add("~/.cache: other small caches", rest, REC, "Small tool caches in ~/.cache.")
    return out

# ---------------------------------------------------------------- Old versions & update leftovers


VERSIONISH = re.compile(r"^v?\d+(\.\d+)+([._+-][A-Za-z0-9._+-]*)?$")
WALK_SKIP = {"node_modules", ".git", "Cache", "Code Cache", "IndexedDB", "Local Storage", "Session Storage",
             "databases", "extensions", "Extensions", "vm_bundles", "Partitions", "GPUCache", "blob_storage"}


def _current_link_versions(roots: List[str], maxdepth: int = 4) -> List[Tuple[str, str, List[str]]]:
    """Find 'current'/'latest' symlinks → older sibling version folders (newer staged ones are kept)."""
    res = []
    seen: Set[str] = set()
    budget = 25000
    for root in roots:
        if not isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            budget -= 1
            if budget <= 0:
                return res
            depth = dirpath[len(root):].count(os.sep)
            for n in list(dirnames) + list(filenames):
                if n.lower() not in ("current", "latest", "active"):
                    continue
                p = os.path.join(dirpath, n)
                if not os.path.islink(p):
                    continue
                tgt = os.path.realpath(p)
                if not isdir(tgt):
                    continue
                P = os.path.dirname(tgt)
                if P in seen or not (P == dirpath or under(P, dirpath) or under(dirpath, root)):
                    continue
                if not under(P, root):
                    continue
                seen.add(P)
                tv = parse_version(os.path.basename(tgt))
                olds = []
                for s in listdir(P):
                    sp = os.path.join(P, s)
                    if sp == tgt or not isdir(sp) or not VERSIONISH.match(s):
                        continue
                    if tv and parse_version(s) >= tv:
                        continue  # newer, probably a staged update — keep
                    olds.append(sp)
                if olds:
                    res.append((P, tgt, olds))
            dirnames[:] = [d for d in dirnames if d not in WALK_SKIP and not os.path.islink(os.path.join(dirpath, d))] \
                if depth < maxdepth else []
    return res


def scan_updates(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    j = os.path.join
    # JetBrains & Android Studio: old version folders
    jb_owners = ["com.jetbrains.intellij", "idea", "IntelliJ IDEA"]
    for base_name, bases in (("JetBrains", [j(AS, "JetBrains"), j(CACHES, "JetBrains"), j(LIB, "Logs", "JetBrains")]),
                             ("Google", [j(AS, "Google"), j(CACHES, "Google"), j(LIB, "Logs", "Google")])):
        for base in bases:
            groups: Dict[str, List[str]] = defaultdict(list)
            for p in children(base):
                m = re.match(r"^([A-Za-z]+?)(\d{4}\.\d+)$", os.path.basename(p))
                if m and isdir(p) and (base_name == "JetBrains" or m.group(1).startswith("AndroidStudio")):
                    groups[m.group(1)].append(p)
            for prod, ps in groups.items():
                if len(ps) < 2:
                    continue
                ps.sort(key=lambda p: parse_version(os.path.basename(p)), reverse=True)
                for old in ps[1:]:
                    ctx.claim(old)
                    out.append(mk("updates", "Old %s %s — %s" % (prod, os.path.basename(old)[len(prod):], os.path.basename(base)),
                                  REC, "Left behind after updating to %s; settings were already imported."
                                  % os.path.basename(ps[0]), paths=[old], owners=jb_owners))
    bk = j(AS, "JetBrains", "Daemon", "bundles", "current.backup")
    if isdir(bk) and os.path.exists(j(AS, "JetBrains", "Daemon", "bundles", "current")):
        out.append(mk("updates", "JetBrains daemon — backup of previous version", REC,
                      "Backup copy kept after the JetBrains background service updated itself.", paths=[bk]))
    # Versions behind a 'current' symlink (Codex, Claude Code, many CLIs and agents)
    roots = [AS, j(HOME, ".local")] + [p for p in children(HOME) if os.path.basename(p).startswith(".")
                                       and isdir(p) and os.path.basename(p) not in (".Trash", ".nvm", ".colima", ".cache",
                                                                                     ".npm", ".m2", ".gradle", ".cargo",
                                                                                     ".rustup", ".git", ".claude",
                                                                                     ".oh-my-zsh", ".vscode", ".cursor")]
    for P, tgt, olds in _current_link_versions(roots):
        olds = [o for o in olds if not ctx.is_claimed(o)]
        if not olds:
            continue
        ctx.claim(*olds)
        out.append(mk("updates", "Old versions in %s" % short(P), REC,
                      "Previous versions kept after an auto-update. Active version %s is kept."
                      % os.path.basename(tgt), paths=olds, location=P))
    # Claude desktop's bundled Claude Code and Google Updater: keep newest
    for title, parent, sudo in (("Claude app — bundled Claude Code", j(AS, "Claude", "claude-code"), False),
                                ("Google Updater", j(AS, "Google", "GoogleUpdater"), False),
                                ("Google Updater (system)", "/Library/Application Support/Google/GoogleUpdater", True)):
        olds = [o for o in _keep_newest_versions(parent, pattern=r"^\d+(\.\d+)+") if not ctx.is_claimed(o)]
        if olds:
            ctx.claim(*olds)
            out.append(mk("updates", "%s — old versions" % title, REC,
                          "Older copies left after the updater installed a newer version.",
                          paths=olds, location=parent, sudo=sudo))
    # Updater payloads
    pay = (glob.glob(j(AS, "Caches", "*-updater")) + glob.glob(j(CACHES, "*-updater")) +
           glob.glob(j(CACHES, "*.ShipIt")) + glob.glob(j(CACHES, "*", "org.sparkle-project.Sparkle")) +
           glob.glob(j(AS, "*", "ShipIt")) + glob.glob(j(CACHES, "com.microsoft.autoupdate*")) +
           glob.glob("/Users/Shared/*/Launcher/SelfUpdateStaging") +
           glob.glob("/Users/Shared/UnrealEngine/Launcher/SelfUpdateStaging"))
    pay = sorted({p for p in pay if os.path.lexists(p) and not ctx.is_claimed(p)})
    if pay:
        ctx.claim(*pay)
        out.append(mk("updates", "Downloaded update installers (Sparkle, Squirrel, electron-updater …)", REC,
                      "Installer payloads apps downloaded to update themselves; already applied or "
                      "re-downloaded on the next update check.", paths=pay))
    ks = [p for p in (j(LIB, "Google", "GoogleSoftwareUpdate"), "/Library/Google/GoogleSoftwareUpdate") if isdir(p)]
    if ks and not _app_installed(ctx, "com.google.Chrome", ["Google Chrome.app"]):
        out.append(mk("updates", "Google Keystone (legacy Google updater)", REV,
                      "Old Google updater, replaced by GoogleUpdater. Only needed by old Google apps.",
                      paths=ks, sudo=any(p.startswith("/Library") for p in ks)))
    # Homebrew
    if shutil.which("brew"):
        benv = {"HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ENV_HINTS": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1"}
        rc, o, e = run(user_cmd(["brew", "cleanup", "-n", "--prune=all", "-s"]), 300, env=benv)
        txt = o + e
        m = re.search(r"free approximately\s+([\d.]+\s*[KMGT]?B)", txt)
        n = len(re.findall(r"^Would remove", txt, re.M))
        ctx.claim(j(CACHES, "Homebrew"))
        if m or n:
            out.append(mk("updates", "Homebrew: old versions & downloads (%d items)" % n, REC,
                          "Outdated formula/cask versions, downloaded bottles and installers.",
                          size=parse_size(m.group(1)) if m else du(j(CACHES, "Homebrew")),
                          action=ACT_CMD, keep_zero=True,
                          cmds=[user_cmd(["brew", "cleanup", "--prune=all", "-s"])]))
        rc, o, e = run(user_cmd(["brew", "autoremove", "-n"]), 180, env=benv)
        names = [l.strip() for l in o.splitlines() if l.strip() and not l.startswith("==>")]
        if names:
            out.append(mk("updates", "Homebrew: %d unused dependencies" % len(names), REV,
                          "Formulae installed only as dependencies that nothing needs now: %s"
                          % trunc(", ".join(names), 160), size=0, action=ACT_CMD, keep_zero=True,
                          cmds=[user_cmd(["brew", "autoremove"])]))
    # Duplicate / older copies of the same app
    bundles: Dict[str, List[Tuple[str, Dict[str, str]]]] = defaultdict(list)
    for root in ("/Applications", j(HOME, "Applications"), j(HOME, "Desktop"), j(HOME, "Documents")):
        for p in children(root):
            if p.endswith(".app"):
                info = bundle_info(p)
                if info["bid"] and not info["bid"].lower().startswith("com.apple."):
                    bundles[info["bid"].lower()].append((p, info))
    for bid, group in bundles.items():
        if len(group) < 2:
            continue
        group.sort(key=lambda x: (parse_version(x[1]["version"]), mtime(x[0])), reverse=True)
        keepp = group[0][0]
        for p, info in group[1:]:
            ctx.claim(p)
            out.append(mk("updates", "Duplicate app: %s (v%s)" % (os.path.basename(p), info["version"] or "?"), REV,
                          "Another copy of the same app (%s v%s) is at %s." %
                          (bid, group[0][1]["version"] or "?", short(keepp)), paths=[p], action=ACT_TRASH,
                          owners=[bid]))
    for p in glob.glob("/Applications/Install macOS*.app"):
        out.append(mk("updates", "macOS installer: %s" % os.path.basename(p), REV,
                      "Full macOS installer (≈13 GB). Keep only if you plan to make a boot USB / reinstall.",
                      paths=[p], action=ACT_TRASH))
    return out

# ---------------------------------------------------------------- Apple apps & devices


def scan_apple(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    j = os.path.join
    mb = j(AS, "MobileSync", "Backup")
    ctx.claim(j(AS, "MobileSync"))
    if os.path.exists(mb):
        try:
            backups = sorted(os.listdir(mb))
        except PermissionError:
            backups = []
            ctx.warnings.append("iPhone/iPad backups need Full Disk Access to be analysed.")
        for b in backups:
            bp = j(mb, b)
            if not isdir(bp):
                continue
            info = read_plist(j(bp, "Info.plist")) or {}
            devname = str(info.get("Device Name") or info.get("Display Name") or b[:12])
            when = info.get("Last Backup Date")
            when_s = when.strftime("%Y-%m-%d") if isinstance(when, _dt.datetime) else "unknown date"
            out.append(mk("apple", "Device backup: %s (%s)" % (devname, when_s), REV,
                          "Local iPhone/iPad backup. Remove it if the device backs up to iCloud or "
                          "you no longer own it.", paths=[bp], action=ACT_TRASH,
                          impact="You can no longer restore the device from this local backup."))
    ipsw = (glob.glob(j(LIB, "iTunes", "*Software Updates", "*.ipsw")) +
            glob.glob(j(LIB, "Group Containers", "*.group.com.apple.configurator", "Library", "Caches", "Firmware", "*.ipsw")))
    if ipsw:
        out.append(mk("apple", "iPhone/iPad firmware files (.ipsw)", REC,
                      "Firmware downloaded to update/restore a device; downloaded again if ever needed.",
                      paths=ipsw))
    md = j(LIB, "Containers", "com.apple.mail", "Data", "Library", "Mail Downloads")
    ctx.claim(md)
    mdp = children(md)
    if mdp:
        out.append(mk("apple", "Mail attachment downloads", REC,
                      "Copies of attachments you opened from Mail. The originals stay in the e-mails.",
                      paths=mdp, location=md, owners=["com.apple.mail", "Mail"]))
    aer = j(AS, "com.apple.wallpaper", "aerials", "videos")
    ctx.claim(j(AS, "com.apple.wallpaper"))
    aerp = children(aer)
    if aerp:
        out.append(mk("apple", "Downloaded Aerial wallpaper/screensaver videos", REV,
                      "4K Aerial videos. macOS downloads the one you use again automatically.",
                      paths=aerp, location=aer,
                      impact="Your Aerial wallpaper may show a still image until it re-downloads."))
    for title, path, why in (
            ("Mail data (mailboxes & attachments)", j(LIB, "Mail"),
             "Manage in Mail: Mailbox ▸ Erase Deleted Items / Erase Junk Mail, and delete large attachments."),
            ("Messages attachments", j(LIB, "Messages", "Attachments"),
             "Review in System Settings ▸ General ▸ Storage ▸ Messages, or enable 'Keep messages: 1 year'."),
            ("iCloud Drive local copies", j(LIB, "Mobile Documents"),
             "Enable System Settings ▸ Apple Account ▸ iCloud ▸ Drive ▸ 'Optimize Mac Storage' to let macOS evict local copies."),
            ("Siri voices", j(LIB, "Group Containers", "group.com.apple.SiriTTS"),
             "Downloaded Siri/Spoken Content voices; remove unused voices in System Settings ▸ Accessibility ▸ Spoken Content."),
    ):
        ctx.claim(path)
        if os.path.exists(path):
            s = du(path)
            if s >= 100e6:
                out.append(mk("apple", title, KEEP, why, paths=[path], size=s, action=ACT_NONE))
    for lib in glob.glob(j(HOME, "Pictures", "*.photoslibrary")):
        out.append(mk("apple", "Photos library: %s" % os.path.basename(lib), KEEP,
                      "Your photos. Empty Photos ▸ Recently Deleted, or use iCloud Photos with "
                      "'Optimize Mac Storage'.", paths=[lib], action=ACT_NONE))
    gb_installed = any(os.path.exists(p) for p in ("/Applications/GarageBand.app", "/Applications/Logic Pro.app",
                                                    "/Applications/Logic Pro X.app", "/Applications/MainStage.app"))
    sound = [p for p in ("/Library/Application Support/GarageBand", "/Library/Application Support/Logic",
                         "/Library/Audio/Apple Loops") if isdir(p)]
    if sound:
        ctx.claim(*sound)
        out.append(mk("apple", "GarageBand / Logic sound library", REV if gb_installed else REC,
                      ("Instrument and loop library used by GarageBand/Logic." if gb_installed else
                       "Sound library of GarageBand/Logic, which are not installed."), paths=sound, sudo=True))
    return out

# ---------------------------------------------------------------- Logs


ROTATED_RE = re.compile(r"(\.(gz|bz2|xz|zip|old|bak)|\.\d+(\.(gz|bz2|xz))?)$")


def scan_logs(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    j = os.path.join
    L = j(LIB, "Logs")
    ctx.claim(LOG_DIR)
    small = []
    for p in children(L, exclude=("clean_mac", "DiagnosticReports")):
        if ctx.is_claimed(p):
            continue
        if du(p) >= 10e6:
            out.append(mk("logs", "Logs: %s" % os.path.basename(p), REC,
                          "Log files written by this app/service. Nothing needs them except troubleshooting.",
                          paths=[p], owners=[os.path.basename(p)]))
        else:
            small.append(p)
    if small:
        out.append(mk("logs", "App & service logs (~/Library/Logs)", REC,
                      "Log files of apps and background services.", paths=small, location=L))
    dr = j(L, "DiagnosticReports")
    drp = children(dr)
    if drp:
        out.append(mk("logs", "Crash & diagnostic reports (yours)", REC,
                      "Crash, hang and resource reports. Only useful when reporting a bug.",
                      paths=drp, location=dr))
    sl = [p for p in children("/Library/Logs", exclude=("DiagnosticReports",)) if du(p) > 0 or isdir(p)]
    if sl:
        out.append(mk("logs", "System logs (/Library/Logs)", REC, "Logs of system-wide installers and services.",
                      paths=sl, location="/Library/Logs", sudo=True))
    sdr = "/Library/Logs/DiagnosticReports"
    if isdir(sdr):
        try:
            names = os.listdir(sdr)
            if names:
                out.append(mk("logs", "Crash & diagnostic reports (system)", REC,
                              "System-wide crash/hang/panic reports.", paths=[j(sdr, n) for n in names],
                              location=sdr, sudo=True))
        except PermissionError:
            out.append(mk("logs", "Crash & diagnostic reports (system)", REC,
                          "System-wide crash/hang/panic reports (size visible to admin only).",
                          paths=[sdr], location=sdr, sudo=True, action=ACT_CONTENTS, keep_zero=True))
    rot = []
    for dirpath, dirnames, filenames in os.walk("/private/var/log"):
        if dirpath.count(os.sep) - "/private/var/log".count(os.sep) >= 2:
            dirnames[:] = []
        for fn in filenames:
            p = j(dirpath, fn)
            if ROTATED_RE.search(fn) or (fn.endswith(".asl") and age_days(p) > 7):
                rot.append(p)
    if rot:
        out.append(mk("logs", "Rotated/archived system logs (/var/log)", REC,
                      "Compressed and numbered old copies of system logs.", paths=rot,
                      location="/private/var/log", sudo=True))
    return out

# ---------------------------------------------------------------- Temp


TEMP_SKIP_PREFIX = ("com.apple.", "tmux-", "ssh-", "vscode-", ".X", "screen", "TemporaryItems",
                    "Cleanup At Startup", "powerlog", "itunescloudd", "launchd", "claude", "zsh",
                    "node-compile-cache", "codex", "gemini", "boost_interprocess", "KSOutOfProcessFetcher")


def _has_socket(p: str) -> bool:
    if not isdir(p):
        return False
    try:
        with os.scandir(p) as it:
            for e in it:
                try:
                    m = e.stat(follow_symlinks=False).st_mode
                    if stat.S_ISSOCK(m) or stat.S_ISFIFO(m):
                        return True
                except OSError:
                    continue
    except OSError:
        return False
    return False


def _stale_temp(d: str, min_days: float) -> List[str]:
    out = []
    for p in children(d):
        n = os.path.basename(p)
        if n.startswith(TEMP_SKIP_PREFIX) or n.endswith((".sock", ".socket", ".lock", ".pid")):
            continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode) or st.st_uid != UID:
            continue
        if _has_socket(p) or newest_mtime(p, depth=2) > NOW - min_days * DAY:
            continue
        out.append(p)
    return out


def scan_temp(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    if USER_TMP:
        p = _stale_temp(USER_TMP, 3)
        if p:
            out.append(mk("temp", "Stale files in your temp folder", REC,
                          "Temporary files no app has touched for 3+ days.", paths=p, location=USER_TMP))
    p = _stale_temp("/private/tmp", 3)
    if p:
        out.append(mk("temp", "Stale files in /tmp (yours)", REC,
                      "Temporary files you own that nothing touched for 3+ days.", paths=p, location="/private/tmp"))
    return out

# ---------------------------------------------------------------- App internal caches


GENERIC_CACHE_NAMES = {"Cache", "Caches", "Code Cache", "GPUCache", "DawnCache", "DawnGraphiteCache",
                       "DawnWebGPUCache", "GraphiteDawnCache", "GrShaderCache", "ShaderCache",
                       "GPUPersistentCache", "CachedData", "Crashpad", "logs", "Logs",
                       "component_crx_cache", "extensions_crx_cache", "Service Worker"}
APP_WALK_SKIP = WALK_SKIP - {"Partitions", "Cache", "Code Cache", "GPUCache"} | {
    "claude-code", "git-worktrees", "scratch-workspaces", "local-agent-mode-sessions", "Backups",
    "backups", "Projects", "projects", "Documents", "Library", "plugins", "Plugins", "bundles",
    "resources", "Resources", "lib", "bin", "app", "runtime", "jbr", "packages", "versions"}


def _app_cache_paths(base: str, maxdepth: int = 4) -> List[str]:
    res: List[str] = []
    for dirpath, dirnames, _ in os.walk(base):
        depth = dirpath[len(base):].count(os.sep)
        keep = []
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if os.path.islink(p) or d.endswith((".app", ".framework", ".bundle", ".plugin", ".asar")):
                continue
            if d in GENERIC_CACHE_NAMES:
                if d == "Crashpad":
                    res += children(os.path.join(p, "completed")) + children(os.path.join(p, "pending"))
                elif d == "Service Worker":
                    res += children(os.path.join(p, "CacheStorage")) + children(os.path.join(p, "ScriptCache"))
                elif d in ("logs", "Logs"):
                    res += children(p, min_age_days=2)
                else:
                    res += children(p)
            elif d not in APP_WALK_SKIP:
                keep.append(d)
        dirnames[:] = keep if depth < maxdepth else []
    return res


def scan_appcache(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    j = os.path.join
    small: List[str] = []
    for n in listdir(AS):
        p = j(AS, n)
        if not isdir(p) or ctx.is_claimed(p):
            continue
        st = ctx.apps.owner(n)
        if st in ("apple", "orphan"):
            continue  # Apple's own data / handled by Leftovers
        paths = [x for x in _app_cache_paths(p) if not ctx.is_claimed(x)]
        if not paths:
            continue
        f = mk("appcache", "%s — internal caches, crash dumps & old logs" % n, REC,
               "Chromium/Electron caches, GPU shader caches, crash dumps and old logs the app "
               "recreates by itself.", paths=paths, location=p, owners=[n],
               impact="The app may start a little slower once. Your data and settings are not touched.")
        if f.size >= 1e6 or ctx.running(n):
            out.append(f)
        else:
            small += paths
    apple_paths: List[str] = []
    analysis: List[str] = []
    for top, label in ((j(LIB, "Containers"), "Data/Library"), (j(LIB, "Group Containers"), "Library")):
        for n in listdir(top):
            cp = j(top, n)
            if not isdir(cp) or ctx.is_claimed(cp):
                continue
            st = ctx.apps.owner(n)
            if st == "orphan":
                continue
            base = j(cp, label)
            paths = children(j(base, "Caches"), min_age_days=1 if st == "apple" else 0) + \
                children(j(base, "Logs"), min_age_days=2)
            if top.endswith("Containers") and not top.endswith("Group Containers"):
                paths += children(j(cp, "Data", "tmp"), min_age_days=2)
            paths = [x for x in paths if not ctx.is_claimed(x)]
            if not paths:
                continue
            if st == "apple":
                if re.search(r"(media|photo)analysisd|wallpaper", n, re.I):
                    analysis += paths
                elif not ctx.running(n):
                    apple_paths += paths
                continue
            f = mk("appcache", "%s — sandbox caches" % n, REC,
                   "Cache folder inside this app's sandbox container.", paths=paths, location=cp, owners=[n])
            if f.size >= 1e6 or ctx.running(n):
                out.append(f)
            else:
                small += paths
    if apple_paths:
        out.append(mk("appcache", "Apple apps — sandbox caches", REC,
                      "Caches inside the containers of Apple apps and services (not running ones). "
                      "Items protected by macOS are skipped automatically.", paths=apple_paths,
                      location=j(LIB, "Containers")))
    if analysis:
        out.append(mk("appcache", "Apple photo/media analysis & wallpaper caches", REV,
                      "Results of on-device photo/video analysis and rendered wallpapers. Safe to delete, "
                      "but macOS will spend CPU/battery re-analysing your library.", paths=analysis,
                      location=j(LIB, "Containers"), impact="Re-created in the background over the next hours."))
    if small:
        out.append(mk("appcache", "Other apps — small caches", REC, "Small caches of various apps.", paths=small,
                      location=AS))
    return out

# ---------------------------------------------------------------- Caches


CACHE_SKIP = {"com.apple.bird", "com.apple.nsurlsessiond", "com.apple.containermanagerd", "com.apple.HomeKit",
              "com.apple.akd", "FamilyCircle", "com.apple.homed", "com.apple.cloudd", "CloudKit",
              "com.apple.ap.adprivacyd", "com.apple.appstoreagent", "com.apple.amsengagementd",
              "com.apple.iCloudHelper", "com.apple.icloud.fmfd", "clean_mac", "com.apple.findmy.fmipcore"}


def scan_caches(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    apple_paths: List[str] = []
    small: List[str] = []
    for n in listdir(CACHES):
        p = os.path.join(CACHES, n)
        if n in CACHE_SKIP or ctx.is_claimed(p) or not isdir(p):
            continue
        st = ctx.apps.owner(n)
        if st == "apple":
            if not ctx.running(n):
                apple_paths += children(p, min_age_days=1)
            continue
        if st == "orphan":
            f = mk("caches", "Cache: %s (app not installed)" % n, REC,
                   "Cache of an app that is no longer installed.", paths=[p])
        else:
            f = mk("caches", "Cache: %s" % n, REC, "Cache files the app re-creates automatically.",
                   paths=children(p), location=p, owners=[n])
        if f.size >= 5e6 or (f.owners and ctx.running(*f.owners)):
            out.append(f)
        elif f.size > 0:
            small += f.paths
    if apple_paths:
        out.append(mk("caches", "macOS & Apple app caches", REC,
                      "Caches of macOS services and Apple apps. Rebuilt automatically; items "
                      "protected by macOS are skipped.", paths=apple_paths, location=CACHES))
    if small:
        out.append(mk("caches", "Other app caches (small)", REC, "Small caches of various apps.",
                      paths=small, location=CACHES))
    sysc = [p for p in children("/Library/Caches", exclude=("com.apple.iconservices.store",))
            if not ctx.is_claimed(p)]
    if sysc:
        out.append(mk("caches", "System-wide caches (/Library/Caches)", REC,
                      "Caches shared by all users (installers, updaters, system services).",
                      paths=sysc, location="/Library/Caches", sudo=True, keep_zero=True))
    return out

# ---------------------------------------------------------------- Leftovers


SKIP_DOTDIRS = {".Trash", ".ssh", ".gnupg", ".config", ".local", ".cache", ".zsh_sessions", ".oh-my-zsh", ".npm",
                ".nvm", ".m2", ".gradle", ".docker", ".kube", ".aws", ".azure", ".gcloud", ".vscode",
                ".vscode-insiders", ".cursor", ".git", ".claude", ".codex", ".gemini", ".colima", ".cargo",
                ".rustup", ".pyenv", ".rbenv", ".sdkman", ".bun", ".deno", ".android", ".pub-cache", ".ollama",
                ".lmstudio", ".jenkins", ".sonarlint", ".terminfo", ".ipython", ".jupyter", ".conda", ".yarn",
                ".pnpm-store", ".matplotlib", ".password-store", ".Secret", ".secret", ".secrets", ".vim",
                ".emacs.d", ".tmux", ".zsh", ".bash_sessions", ".cups", ".swiftpm", ".dotnet", ".nuget",
                ".minikube", ".helm", ".terraform.d", ".pulumi", ".antigravity", ".antigravity-ide",
                ".continue", ".copilot", ".qwen", ".opencode", ".kilocode", ".cline", ".junie",
                ".clean_mac_ignore", ".wdm", ".node-gyp", ".electron-gyp", ".cocoapods", ".fastlane",
                ".bundle", ".gem", ".rvm", ".asdf", ".mise", ".volta", ".fnm", ".jdks", ".sts4"}
CRED_RE = re.compile(r"(id_rsa|id_ed25519|id_ecdsa|\.pem$|\.key$|credential|token|auth\.json|secret|\.p12$|"
                     r"wallet|keystore|\.kdbx$|private|\.gpg$|\.asc$|password)", re.I)


def _has_credentials(p: str) -> bool:
    count = 0
    for dirpath, dirnames, filenames in os.walk(p):
        if dirpath[len(p):].count(os.sep) >= 2:
            dirnames[:] = []
        for fn in filenames:
            count += 1
            if CRED_RE.search(fn):
                return True
            if count > 300:
                return False
    return False


def scan_leftovers(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    j = os.path.join
    # (folder, kind, recommendation for orphans, sudo, action)
    locs = [
        (AS, "app data", REV, False, ACT_TRASH),
        (j(LIB, "Containers"), "sandbox container", None, False, ACT_TRASH),
        (j(LIB, "Group Containers"), "shared group container", REV, False, ACT_TRASH),
        (j(LIB, "Preferences"), "preferences", REC, False, ACT_DELETE),
        (j(LIB, "Preferences", "ByHost"), "preferences (ByHost)", REC, False, ACT_DELETE),
        (j(LIB, "Saved Application State"), "saved window state", REC, False, ACT_DELETE),
        (j(LIB, "HTTPStorages"), "HTTP storage", REC, False, ACT_DELETE),
        (j(LIB, "WebKit"), "WebKit storage", REC, False, ACT_DELETE),
        (j(LIB, "Cookies"), "cookies", REC, False, ACT_DELETE),
        (j(LIB, "Application Scripts"), "app scripts", REC, False, ACT_DELETE),
        ("/Library/Application Support", "system-wide app data", REV, True, ACT_DELETE),
        ("/Users/Shared", "shared files", REV, False, ACT_TRASH),
    ]
    relocated: List[str] = []
    for folder, kind, rec, sudo, action in locs:
        for n in listdir(folder):
            p = j(folder, n)
            if n.startswith(".") or ctx.is_claimed(p) or is_ignored(p, ctx.ignore):
                continue
            is_file = os.path.isfile(p) and not os.path.islink(p)
            if folder.endswith("Preferences") or folder.endswith("ByHost"):
                if not is_file or not n.endswith(".plist") or not BID_RE.match(n[:-6].lower()):
                    continue
            elif folder.endswith(("Saved Application State",)):
                if not n.endswith(".savedState"):
                    continue
            elif folder == j(LIB, "Cookies"):
                if not n.endswith(".binarycookies") or n == "Cookies.binarycookies":
                    continue
            elif not isdir(p):
                continue
            if folder == "/Users/Shared" and n.startswith("Previously Relocated Items"):
                relocated.append(p)
                continue
            st = ctx.apps.owner(n)
            if st in ("apple", "installed"):
                continue
            r = rec
            if folder.endswith("Containers") and not folder.endswith("Group Containers"):
                r = REC if du(p) < 20e6 else REV
            if st == "vendor":
                if du(p) < 1e6:
                    continue
                r = REV
            min_age = 7 if r == REC else 14
            if newest_mtime(p, depth=2) > NOW - min_age * DAY:
                continue  # touched recently → something still uses it
            why = ("No installed app matches '%s'." % n) if st == "orphan" else \
                ("The vendor still has other apps installed, but none that uses '%s'." % n)
            out.append(mk("leftovers", "%s — %s" % (n, kind), r, why + " Not modified for %d days."
                          % int(age_days(p)), paths=[p], sudo=sudo, action=action if not sudo else ACT_DELETE,
                          impact=("Moved to Trash (recoverable)." if action == ACT_TRASH and not sudo else
                                  "If you reinstall the app it starts with default settings.")))
    if relocated:
        out.append(mk("leftovers", "Previously Relocated Items (%d folders from macOS upgrades)" % len(relocated), REV,
                      "Files macOS moved aside during upgrades because they conflicted with the new "
                      "system (usually old config files). Safe to delete after a quick look.",
                      paths=relocated, location="/Users/Shared", action=ACT_TRASH))
    for p in children(HOME):
        n = os.path.basename(p)
        if not n.startswith(".") or not isdir(p) or n in SKIP_DOTDIRS or ctx.is_claimed(p):
            continue
        if is_ignored(p, ctx.ignore) or ctx.apps.owner(n.lstrip(".")) != "orphan":
            continue
        if newest_mtime(p, depth=2) > NOW - 30 * DAY or _has_credentials(p):
            continue
        out.append(mk("leftovers", "~/%s — tool data folder" % n, REV,
                      "Hidden folder of a tool/app that does not seem to be installed; not touched for "
                      "%d days." % int(age_days(p)), paths=[p], action=ACT_TRASH,
                      impact="Moved to Trash (recoverable)."))
    return out

# ---------------------------------------------------------------- Startup items, plug-ins, receipts


def scan_startup(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    j = os.path.join
    daemon_progs: Set[str] = set()
    for d, sudo in ((j(LIB, "LaunchAgents"), False), ("/Library/LaunchAgents", True), ("/Library/LaunchDaemons", True)):
        for n in listdir(d):
            if not n.endswith(".plist"):
                continue
            p = j(d, n)
            label = n[:-6]
            if os.path.islink(p) and not os.path.exists(p):
                out.append(mk("startup", "Broken startup item: %s" % label, REC,
                              "Link to a launch item whose file was removed (%s)." % os.readlink(p),
                              paths=[p], action=ACT_LAUNCHD, sudo=sudo, keep_zero=True))
                continue
            data = read_plist(p)
            if data is None:
                out.append(mk("startup", "Unreadable startup item: %s" % label, REV,
                              "This launch item is corrupt or unreadable; launchd ignores it.", paths=[p],
                              action=ACT_LAUNCHD, sudo=sudo, keep_zero=True))
                continue
            if not data:
                out.append(mk("startup", "Empty placeholder startup item: %s" % label, REV,
                              "An empty launch item (Google's updater leaves these to disable the old "
                              "Keystone updater). Harmless but useless.", paths=[p], action=ACT_LAUNCHD,
                              sudo=sudo, keep_zero=True))
                continue
            label = str(data.get("Label") or label)
            prog = data.get("Program")
            if not prog:
                args = data.get("ProgramArguments")
                prog = args[0] if isinstance(args, list) and args else None
            if not isinstance(prog, str) or not prog.startswith("/"):
                continue
            daemon_progs.add(prog)
            if not os.path.exists(prog):
                out.append(mk("startup", "Broken startup item: %s" % label, REC,
                              "Starts %s, which no longer exists — macOS retries it in vain." % prog,
                              paths=[p], action=ACT_LAUNCHD, sudo=sudo, keep_zero=True))
                continue
            if ctx.apps.owner(label) == "orphan":
                extra = [prog] if prog.startswith("/Library/PrivilegedHelperTools/") else []
                out.append(mk("startup", "Startup item of an uninstalled app: %s" % label, REV,
                              "Runs %s at startup, but its app is not installed." % short(prog),
                              paths=[p] + extra, action=ACT_LAUNCHD, sudo=sudo, keep_zero=True))
                ctx.claim(*extra)
    for n in listdir("/Library/PrivilegedHelperTools"):
        p = j("/Library/PrivilegedHelperTools", n)
        if p in daemon_progs or ctx.is_claimed(p):
            continue
        if not os.path.exists(j("/Library/LaunchDaemons", n + ".plist")):
            out.append(mk("startup", "Privileged helper without launch daemon: %s" % n, REV,
                          "A root helper tool that nothing launches any more (left by an uninstalled app).",
                          paths=[p], sudo=True, keep_zero=True))
    plug_dirs = [
        ("/Library/Audio/Plug-Ins/HAL", True, "audio driver"), (j(LIB, "Audio", "Plug-Ins", "HAL"), False, "audio driver"),
        ("/Library/Audio/Plug-Ins/Components", True, "audio unit"), (j(LIB, "Audio", "Plug-Ins", "Components"), False, "audio unit"),
        ("/Library/Internet Plug-Ins", True, "internet plug-in"), (j(LIB, "Internet Plug-Ins"), False, "internet plug-in"),
        ("/Library/PreferencePanes", True, "System Settings pane"), (j(LIB, "PreferencePanes"), False, "System Settings pane"),
        ("/Library/Screen Savers", True, "screen saver"), (j(LIB, "Screen Savers"), False, "screen saver"),
        ("/Library/QuickLook", True, "Quick Look plug-in"), (j(LIB, "QuickLook"), False, "Quick Look plug-in"),
        ("/Library/Spotlight", True, "Spotlight importer"), (j(LIB, "Spotlight"), False, "Spotlight importer"),
        ("/Library/Input Methods", True, "input method"), (j(LIB, "Input Methods"), False, "input method"),
        (j(LIB, "Services"), False, "Services menu item"),
    ]
    for d, sudo, kind in plug_dirs:
        for n in listdir(d):
            p = j(d, n)
            if n.startswith(".") or n.endswith(".workflow") or "." not in n:
                continue  # only real bundles (e.g. .driver, .plugin, .prefPane, .mdimporter)
            bid = bundle_info(p).get("bid") or n
            st = ctx.apps.owner(bid)
            if st == "orphan" and ctx.apps.owner(os.path.splitext(n)[0]) == "orphan":
                out.append(mk("startup", "%s: %s" % (kind.capitalize(), n), REV,
                              "A %s (%s) whose app is not installed." % (kind, bid), paths=[p],
                              sudo=sudo, action=ACT_DELETE if sudo else ACT_TRASH))
    rc, o, _ = run(["pkgutil", "--pkgs"], 30)
    for pid in sorted(set(o.split())):
        if pid.lower().startswith("com.apple."):
            continue
        rc2, info, _ = run(["pkgutil", "--pkg-info", pid], 15)
        vol = re.search(r"^volume:\s*(.*)$", info, re.M)
        loc = re.search(r"^location:\s*(.*)$", info, re.M)
        base = os.path.join(vol.group(1).strip() if vol else "/", loc.group(1).strip() if loc else "")
        rc3, files, _ = run(["pkgutil", "--only-files", "--files", pid], 30)
        fl = [x for x in files.splitlines() if x.strip()][:60]
        if not fl:
            continue
        if not any(os.path.lexists(os.path.join(base, f)) for f in fl):
            out.append(mk("startup", "Installer receipt of removed package: %s" % pid, REC,
                          "macOS still remembers this package as installed, but none of its files exist.",
                          size=0, action=ACT_CMD, sudo=True, keep_zero=True,
                          cmds=[["pkgutil", "--forget", pid]]))
    return out

# ---------------------------------------------------------------- Unused applications


def _mdls_dates(path: str) -> Tuple[Optional[_dt.datetime], Optional[_dt.datetime]]:
    rc, o, _ = run(["mdls", "-name", "kMDItemLastUsedDate", "-name", "kMDItemDateAdded", "-raw", path], 15)
    vals = o.split("\0") if "\0" in o else o.splitlines()
    res: List[Optional[_dt.datetime]] = []
    for v in vals[:2]:
        v = v.strip()
        try:
            res.append(_dt.datetime.strptime(v, "%Y-%m-%d %H:%M:%S %z"))
        except ValueError:
            res.append(None)
    while len(res) < 2:
        res.append(None)
    return res[0], res[1]


def scan_unused(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    limit = ctx.opts.unused_days
    nowdt = _dt.datetime.now(_dt.timezone.utc)
    for root in ("/Applications", os.path.join(HOME, "Applications")):
        for p in children(root):
            if not p.endswith(".app"):
                continue
            info = bundle_info(p)
            bid = info["bid"]
            webapp = bid.lower().startswith("com.apple.safari.webapp")
            if not bid or (bid.lower().startswith("com.apple.") and not webapp) or \
                    ctx.running(bid, info["name"], os.path.basename(p)[:-4]):
                continue
            last, added = _mdls_dates(p)
            if last:
                days = (nowdt - last).days
                if days < limit:
                    continue
                why = "Last opened %d days ago (%s)." % (days, last.strftime("%Y-%m-%d"))
            elif added and (nowdt - added).days >= limit:
                why = "Never opened since it was added %d days ago." % (nowdt - added).days
            else:
                continue
            out.append(mk("unused", "%s %s" % (os.path.basename(p)[:-4], info["version"]), REV,
                          why + " Uninstall it if you don't need it.", paths=[p], action=ACT_TRASH, owners=[bid],
                          impact="Moved to Trash. Re-run clean_mac afterwards to remove its leftovers "
                                 "(or use AppCleaner)."))
    return out

# ---------------------------------------------------------------- Downloads


ARCHIVE_EXTS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz")


def _mounted_images() -> Set[str]:
    rc, o, _ = run(["hdiutil", "info"], 20)
    return {m.group(1).strip() for m in re.finditer(r"^image-path\s*:\s*(.+)$", o, re.M)}


def scan_downloads(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    D = os.path.join(HOME, "Downloads")
    mounted = _mounted_images()
    old_days = ctx.opts.old_days
    for p in children(D, exclude=(".DS_Store", ".localized")):
        try:
            st = os.lstat(p)
        except OSError:
            continue
        n = os.path.basename(p)
        low = n.lower()
        added = max(st.st_mtime, getattr(st, "st_birthtime", 0) or 0)
        age = (NOW - added) / DAY
        is_d = stat.S_ISDIR(st.st_mode)
        f = None
        if low.endswith(PARTIAL_EXTS):
            if age > 1:
                f = mk("downloads", "Incomplete download: %s" % n, REC,
                       "A download that never finished (%d days old)." % age, paths=[p], action=ACT_TRASH)
        elif low.endswith((".dmg", ".pkg", ".mpkg", ".xip")) and not is_d or low.endswith((".pkg", ".mpkg")):
            if p in mounted:
                continue
            if age >= 2:
                f = mk("downloads", "Installer: %s" % n, REC,
                       "Installer downloaded %d days ago — the app is normally installed already." % age,
                       paths=[p], action=ACT_TRASH, impact="Moved to Trash; download it again if needed.")
        elif low.endswith(".app") and is_d:
            info = bundle_info(p)
            if info["bid"] and ctx.apps.has_bid(info["bid"]) and ctx.apps.bid_paths.get(info["bid"].lower(), "") != p:
                f = mk("downloads", "App copy: %s" % n, REC,
                       "The same app (%s) is already installed at %s." %
                       (info["bid"], short(ctx.apps.bid_paths.get(info["bid"].lower(), "/Applications"))),
                       paths=[p], action=ACT_TRASH)
            else:
                f = mk("downloads", "App in Downloads: %s" % n, REV,
                       "Apps should live in /Applications. Move it there, or delete it if unused.",
                       paths=[p], action=ACT_TRASH)
        elif low.endswith(ARCHIVE_EXTS) and not is_d:
            stem = n
            for e in ARCHIVE_EXTS:
                if low.endswith(e):
                    stem = n[: -len(e)]
                    break
            if stem and os.path.exists(os.path.join(D, stem)) and age >= 7:
                f = mk("downloads", "Already-extracted archive: %s" % n, REC,
                       "Its contents were extracted to '%s'." % stem, paths=[p], action=ACT_TRASH)
            elif age >= old_days:
                f = mk("downloads", "Old archive: %s" % n, REV, "Not touched for %d days." % age,
                       paths=[p], action=ACT_TRASH)
        elif low.endswith(".torrent") and age > 7:
            f = mk("downloads", "Torrent file: %s" % n, REC,
                   "Small .torrent link file; the download itself is elsewhere.", paths=[p], action=ACT_TRASH)
        elif age >= old_days:
            f = mk("downloads", "Old download: %s" % n, REV,
                   "In Downloads and not touched for %d days." % age, paths=[p], action=ACT_TRASH)
        if f:
            ctx.claim(p)
            out.append(f)
    return out

# ---------------------------------------------------------------- Walk-based areas


def scan_projects(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    w = ctx.walk()
    pyc, pytool = [], []
    for kind, p, proj, stale in w.junk:
        if ctx.is_claimed(p):
            continue
        sp = short(proj)
        if kind == "node_modules":
            out.append(mk("projects", "node_modules — %s" % sp, REC if stale >= 30 else REV,
                          "Installed JS dependencies; project untouched for %d days." % stale, paths=[p],
                          impact="Run npm/yarn/pnpm install to get them back."))
        elif kind == "venv":
            out.append(mk("projects", "Python environment — %s" % short(p), REV,
                          "Virtual environment; project untouched for %d days." % stale, paths=[p],
                          impact="Recreate it and reinstall requirements when you work on it again."))
        elif kind == "build":
            out.append(mk("projects", "Build output %s — %s" % (os.path.basename(p), sp),
                          REC if stale >= 14 else REV,
                          "Compiled output/caches regenerated by the next build; project untouched "
                          "for %d days." % stale, paths=[p]))
        elif kind == "pycache":
            pyc.append(p)
        elif kind == "pytool":
            pytool.append(p)
    if pyc:
        out.append(mk("projects", "Python bytecode caches (__pycache__) — %d folders" % len(pyc), REC,
                      "Compiled .pyc files; Python recreates them automatically.", paths=pyc))
    if pytool:
        out.append(mk("projects", "pytest/mypy/ruff caches — %d folders" % len(pytool), REC,
                      "Tool caches; recreated on the next run.", paths=pytool))
    return out


def scan_clutter(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    w = ctx.walk()
    if w.ds_store:
        out.append(mk("clutter", ".DS_Store files (%d)" % len(w.ds_store), REC,
                      "Finder view-settings files. Finder recreates them when needed.",
                      paths=w.ds_store, keep_zero=True, impact="Folders may forget icon positions/view style."))
    if w.appledouble:
        out.append(mk("clutter", "AppleDouble '._' files (%d)" % len(w.appledouble), REC,
                      "Metadata shadow files copied from non-Mac drives.", paths=w.appledouble, keep_zero=True))
    if w.office_tmp:
        out.append(mk("clutter", "Office temporary/lock files (%d)" % len(w.office_tmp), REC,
                      "~$ files left behind by Word/Excel/PowerPoint.", paths=w.office_tmp, keep_zero=True))
    if w.partial:
        part = [p for p in w.partial if not ctx.is_claimed(p)]
        if part:
            out.append(mk("clutter", "Incomplete downloads elsewhere (%d)" % len(part), REC,
                          "Unfinished download files older than 2 days.", paths=part, action=ACT_TRASH))
    bl_out = [p for p, repo in w.broken if not repo]
    bl_repo = [p for p, repo in w.broken if repo]
    for d in {os.path.join(HOME, "bin"), os.path.join(HOME, ".local", "bin"), "/usr/local/bin", "/opt/homebrew/bin"}:
        for p in children(d):
            if os.path.islink(p) and not os.path.exists(p):
                bl_out.append(p)
    sys_bl = [p for p in bl_out if p.startswith("/usr/local/bin") and not os.access("/usr/local/bin", os.W_OK)]
    usr_bl = [p for p in bl_out if p not in sys_bl]
    if usr_bl:
        out.append(mk("clutter", "Broken symbolic links (%d)" % len(usr_bl), REC,
                      "Shortcuts pointing to files that no longer exist.", paths=usr_bl, keep_zero=True))
    if sys_bl:
        out.append(mk("clutter", "Broken links in /usr/local/bin (%d)" % len(sys_bl), REC,
                      "Commands whose program was uninstalled.", paths=sys_bl, sudo=True, keep_zero=True))
    if bl_repo:
        out.append(mk("clutter", "Broken links inside git projects (%d)" % len(bl_repo), REV,
                      "May be intentional in a repository — review.", paths=bl_repo, keep_zero=True))
    empties = [p for p in w.empty_dirs if not ctx.is_claimed(p)]
    if empties:
        out.append(mk("clutter", "Empty folders (%d)" % len(empties), REV,
                      "Folders with nothing inside (outside git projects).", paths=empties, keep_zero=True))
    rc, o, _ = run(user_cmd(["defaults", "read", "com.apple.screencapture", "location"]), 10)
    loc = os.path.expanduser(o.strip()) if rc == 0 and o.strip() else os.path.join(HOME, "Desktop")
    shots = [p for p in children(loc) if os.path.isfile(p) and not os.path.islink(p)
             and re.match(r"^(Screenshot|Screen Shot|Screen Recording|CleanShot|Bildschirmfoto)", os.path.basename(p))
             and age_days(p) >= 30 and not ctx.is_claimed(p)]
    if shots:
        out.append(mk("clutter", "Old screenshots & screen recordings (%d)" % len(shots), REV,
                      "Screenshots older than 30 days in %s." % short(loc), paths=shots, action=ACT_TRASH))
    return out


FILE_KINDS = [((".mov", ".mp4", ".mkv", ".avi", ".m4v", ".webm"), "video"),
              ((".dmg", ".iso", ".img", ".pkg"), "disk image / installer"),
              ((".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".xz"), "archive"),
              ((".vmdk", ".vdi", ".qcow2", ".utm", ".pvm", ".vmwarevm", ".raw", ".hdd"), "virtual-machine disk"),
              ((".log", ".txt"), "log/text"), ((".ipa", ".apk", ".aab"), "app package"),
              ((".psd", ".tif", ".tiff", ".raw", ".cr2", ".nef"), "image"), ((".wav", ".aiff", ".flac"), "audio")]


def scan_large(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    items = sorted(ctx.walk().large, reverse=True)
    for sz, p in items[:40]:
        if ctx.is_claimed(p):
            continue
        kind = "file"
        for exts, k in FILE_KINDS:
            if p.lower().endswith(exts):
                kind = k
                break
        out.append(mk("large", "%s (%s)" % (os.path.basename(p), kind), REV,
                      "Large %s, last modified %d days ago. Delete or move to an external drive if you "
                      "don't need it here." % (kind, age_days(p)), paths=[p], size=sz, action=ACT_TRASH,
                      location=p))
    return out


def scan_dupes(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    D = os.path.join(HOME, "Downloads")
    for g in ctx.walk().dupes():
        g = [p for p in g if os.path.exists(p)]
        if len(g) < 2:
            continue
        g.sort(key=lambda p: (1 if p.startswith(D + "/") else 0, mtime(p), len(p)))
        keep, rest = g[0], g[1:]
        out.append(mk("dupes", "Duplicate ×%d: %s" % (len(g), os.path.basename(keep)), REV,
                      "Identical content (SHA-1 verified). Keeping %s." % short(keep),
                      paths=rest, action=ACT_TRASH, location=keep))
    out.sort(key=lambda f: f.size, reverse=True)
    return out

# ---------------------------------------------------------------- Maintenance


def scan_maint(ctx: Ctx) -> List[Finding]:
    out: List[Finding] = []
    qlc = os.path.join(USER_CACHE, "com.apple.QuickLook.thumbnailcache") if USER_CACHE else ""
    out.append(mk("maint", "Reset Quick Look thumbnail cache", REC,
                  "Fixes wrong/stale thumbnails and frees the thumbnail cache.",
                  size=du(qlc) if qlc else 0, action=ACT_CMD, keep_zero=True,
                  cmds=[["qlmanage", "-r", "cache"], ["qlmanage", "-r"]]))
    if os.path.exists(LSREGISTER):
        out.append(mk("maint", "Clean LaunchServices database", REC,
                      "Garbage-collects registrations of deleted apps (fixes duplicate 'Open With' entries).",
                      size=0, action=ACT_CMD, keep_zero=True, cmds=[[LSREGISTER, "-gc"]]))
    out.append(mk("maint", "Flush DNS cache", REV,
                  "Only needed if websites fail to resolve or after changing DNS / hosts file.",
                  size=0, action=ACT_CMD, sudo=True, keep_zero=True,
                  cmds=[["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]]))
    out.append(mk("maint", "Reset font caches", REV,
                  "Fixes garbled or missing fonts. Log out or restart afterwards.", size=0, action=ACT_CMD,
                  keep_zero=True, cmds=[["atsutil", "databases", "-removeUser"]]))
    out.append(mk("maint", "Free inactive memory (purge)", REV,
                  "Drops disk caches from RAM. Rarely needed; macOS manages memory itself.", size=0,
                  action=ACT_CMD, sudo=True, keep_zero=True, cmds=[["purge"]]))
    out.append(mk("maint", "Rebuild Spotlight index", REV,
                  "Only if search results are missing/wrong. Re-indexing takes a while.", size=0,
                  action=ACT_CMD, sudo=True, keep_zero=True, cmds=[["mdutil", "-E", "/"]]))
    out.append(mk("maint", "Review Login Items & background apps", REV,
                  "Opens System Settings ▸ General ▸ Login Items so you can disable apps you don't "
                  "need at startup.", size=0, action=ACT_CMD, keep_zero=True,
                  cmds=[["open", "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"]]))
    return out


SCANNERS = {
    "trash": scan_trash, "snapshots": scan_snapshots, "browsers": scan_browsers, "editors": scan_editors,
    "xcode": scan_xcode, "docker": scan_docker, "dev": scan_dev, "updates": scan_updates, "apple": scan_apple,
    "logs": scan_logs, "temp": scan_temp, "appcache": scan_appcache, "caches": scan_caches,
    "leftovers": scan_leftovers, "startup": scan_startup, "downloads": scan_downloads,
    "projects": scan_projects, "clutter": scan_clutter, "large": scan_large, "dupes": scan_dupes,
    "unused": scan_unused, "maint": scan_maint,
}


def finalize(ctx: Ctx, f: Finding) -> Optional[Finding]:
    if f.paths:
        kept = [p for p in f.paths if not is_ignored(p, ctx.ignore)]
        if len(kept) != len(f.paths):
            f.paths = kept
            f.size = sum(du(p) for p in kept) if f.action != ACT_CMD else f.size
    if f.location and is_ignored(f.location, ctx.ignore) and f.action != ACT_NONE:
        return None
    if f.action in PATH_ACTIONS + (ACT_EMPTY_TRASH,) and not f.paths:
        return None
    if f.size <= 0 and not f.keep_zero:
        return None
    if f.owners:
        f.running = ctx.running(*f.owners)
    return f


def scan_all(ctx: Ctx, areas: Optional[Set[str]] = None, quiet: bool = False) -> Dict[str, List[Finding]]:
    results: Dict[str, List[Finding]] = {k: [] for k, _, _ in AREAS}
    tty = sys.stderr.isatty() and not quiet
    for key in SCAN_ORDER:
        if key in WALK_AREAS and areas is not None and key not in areas:
            continue
        if tty:
            sys.stderr.write("\r\033[K  " + c("Scanning", CYAN) + " %s …" % AREA_TITLE[key])
            sys.stderr.flush()
        try:
            found = SCANNERS[key](ctx)
        except KeyboardInterrupt:
            raise
        except Exception as e:  # a broken scanner must never break the tool
            ctx.warnings.append("Scanner '%s' skipped: %s" % (AREA_TITLE[key], e))
            LOG.write("ERROR", "scanner %s: %r" % (key, e))
            found = []
        fs = []
        for f in found:
            g = finalize(ctx, f)
            if g:
                fs.append(g)
        fs.sort(key=lambda x: (REC_ORDER[x.rec], -x.size))
        results[key] = fs
    if tty:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
    if areas is not None:
        for k in list(results):
            if k not in areas:
                results[k] = []
    return results

# =============================================================================
# Execution
# =============================================================================

_SUDO_OK: Optional[bool] = None


def ensure_sudo(interactive: bool = True) -> bool:
    global _SUDO_OK
    if IS_ROOT:
        return True
    if _SUDO_OK:
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
            return True
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0:
        _SUDO_OK = True
        return True
    if not interactive or not sys.stdin.isatty():
        _SUDO_OK = False
        return False
    print(c("  Some items need administrator rights — macOS will ask for your password.", YELLOW))
    _SUDO_OK = subprocess.run(["sudo", "-v"]).returncode == 0
    return bool(_SUDO_OK)


def _sudo(cmd: List[str]) -> List[str]:
    return cmd if IS_ROOT else ["sudo", "-n"] + cmd


def _clear_flags(p: str):
    try:
        if hasattr(os, "lchflags"):
            os.lchflags(p, 0)
    except OSError:
        pass
    try:
        parent = os.path.dirname(p)
        os.chmod(parent, os.stat(parent).st_mode | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRUSR)
    except OSError:
        pass
    try:
        if isdir(p):
            os.chmod(p, os.lstat(p).st_mode | stat.S_IRWXU)
    except OSError:
        pass


def remove_path(p: str) -> Tuple[bool, int, str]:
    """Permanently delete p. Returns (fully_removed, bytes_freed, error)."""
    _DU.pop(p, None)
    before = du(p)
    _DU.pop(p, None)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return True, 0, ""
    except OSError as e:
        return False, 0, str(e)
    errs: List[str] = []

    def onerror(func, path, exc_info):
        _clear_flags(path)
        try:
            func(path)
        except Exception as e:
            errs.append("%s: %s" % (short(path), getattr(e, "strerror", None) or e))

    try:
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(p, onerror=onerror)
        else:
            try:
                os.unlink(p)
            except PermissionError:
                _clear_flags(p)
                os.unlink(p)
    except Exception as e:
        errs.append(str(getattr(e, "strerror", None) or e))
    gone = not os.path.lexists(p)
    after = 0 if gone else du(p)
    _DU.pop(p, None)
    return gone, max(0, before - after), (errs[0] if errs else "")


def move_to_trash(p: str) -> Tuple[bool, int, str]:
    size = du(p)
    trash = os.path.join(HOME, ".Trash")
    base = os.path.basename(p.rstrip("/"))
    dest = os.path.join(trash, base)
    if os.path.lexists(dest):
        stem, ext = os.path.splitext(base)
        if base.endswith(".app"):
            stem, ext = base[:-4], ".app"
        dest = os.path.join(trash, "%s %s%s" % (stem, time.strftime("%H.%M.%S"), ext))
    try:
        os.rename(p, dest)
        return True, size, ""
    except OSError as e:
        esc = p.replace("\\", "\\\\").replace('"', '\\"')
        script = 'tell application "Finder" to delete (POSIX file "%s" as alias)' % esc
        rc, _, err = run(["osascript", "-e", script], 180)
        if rc == 0 or not os.path.lexists(p):
            return True, size, ""
        return False, 0, (err.strip() or str(e))


class Executor:
    def __init__(self, ctx: Ctx, dry_run: bool):
        self.ctx = ctx
        self.dry = dry_run

    def _paths_ok(self, f: Finding) -> List[str]:
        good = []
        for p in f.paths:
            probe = os.path.join(p, "__child__") if f.action == ACT_CONTENTS else p
            ok, why = is_safe(probe, f.action)
            if not ok:
                LOG.write("REFUSED", "%s (%s)" % (p, why))
                f.note = "some paths refused: %s" % why
                continue
            if is_ignored(p, self.ctx.ignore):
                continue
            good.append(p)
        return good

    def run_one(self, f: Finding) -> int:
        if f.action == ACT_NONE:
            f.status = "skipped"
            f.note = "information only"
            return 0
        if self.dry:
            f.status = "dry"
            LOG.write("DRYRUN", "%s [%s] %s" % (f.title, human(f.size), f.where()))
            return f.size
        freed = 0
        fails = 0
        first_err = ""
        if f.action == ACT_EMPTY_TRASH:
            freed, fails, first_err = self._empty_trash(f)
        elif f.action == ACT_CMD:
            ok = True
            df0, _ = disk_free()
            for cmd in f.cmds:
                full = _sudo(cmd) if f.sudo else cmd
                LOG.write("RUN", " ".join(full))
                try:
                    rc = subprocess.run(full, stdin=subprocess.DEVNULL).returncode
                except FileNotFoundError:
                    rc = 127
                if rc != 0:
                    ok = False
                    first_err = "%s exited with %d" % (cmd[0], rc)
            df1, _ = disk_free()
            freed = max(df1 - df0, f.size if ok else 0)
            fails = 0 if ok else 1
        else:
            paths = self._paths_ok(f)
            for p in paths:
                if f.action == ACT_TRASH:
                    ok, fr, err = move_to_trash(p)
                    LOG.write("TRASH" if ok else "FAIL", "%s %s %s" % (p, human(fr), err))
                elif f.sudo and not IS_ROOT:
                    ok, fr, err = self._sudo_remove(p, f.action)
                else:
                    if f.action == ACT_LAUNCHD:
                        self._bootout(p, f.sudo)
                    if f.action == ACT_CONTENTS:
                        fr = 0
                        ok = True
                        err = ""
                        for ch in children(p):
                            o2, f2, e2 = remove_path(ch)
                            fr += f2
                            if not o2:
                                ok, err = False, e2
                    else:
                        ok, fr, err = remove_path(p)
                    LOG.write("DELETE" if ok else "PARTIAL", "%s %s %s" % (p, human(fr), err))
                freed += fr
                if not ok:
                    fails += 1
                    first_err = first_err or err
            if not paths:
                fails = max(fails, 1)
                first_err = first_err or f.note or "nothing to remove"
        f.freed = freed
        if fails == 0:
            f.status = "done"
        elif freed > 0:
            f.status = "partial"
            f.note = "%d item(s) could not be removed (%s)" % (fails, trunc(first_err or "protected by macOS", 80))
        else:
            f.status = "failed"
            f.note = trunc(first_err or "could not remove", 100)
        return freed

    def _bootout(self, plist: str, sudo: bool):
        if not plist.endswith(".plist"):
            return
        if plist.startswith("/Library/LaunchDaemons"):
            domain = "system"
        elif plist.startswith("/Library/LaunchAgents"):
            domain = "gui/%d" % UID
        else:
            domain = "gui/%d" % UID
        cmd = ["launchctl", "bootout", domain, plist]
        if sudo and domain == "system":
            cmd = _sudo(cmd)
        run(cmd, 20)

    def _sudo_remove(self, p: str, action: str) -> Tuple[bool, int, str]:
        size = du(p)
        if action == ACT_LAUNCHD:
            self._bootout(p, True)
        if action == ACT_CONTENTS:
            cmd = _sudo(["find", p, "-mindepth", "1", "-maxdepth", "1", "-exec", "rm", "-rf", "{}", "+"])
        else:
            cmd = _sudo(["rm", "-rf", "--", p])
        rc, _, err = run(cmd, 600)
        LOG.write("SUDO-RM" if rc == 0 else "FAIL", "%s %s %s" % (p, human(size), err.strip()))
        if rc == 0:
            return True, size, ""
        return False, 0, err.strip() or "rm failed"

    def _empty_trash(self, f: Finding) -> Tuple[int, int, str]:
        freed = 0
        t = os.path.join(HOME, ".Trash")
        listed = True
        fails = 0
        err = ""
        try:
            names = os.listdir(t)
        except OSError:
            names, listed = [], False
        for n in names:
            ok, fr, e = remove_path(os.path.join(t, n))
            freed += fr
            if not ok:
                fails += 1
                err = err or e
        LOG.write("EMPTY", "~/.Trash %s" % human(freed))
        if not listed or len(f.paths) > 1 or fails:
            rc, _, e = run(["osascript", "-e", 'tell application "Finder" to empty the trash'], 600)
            if rc == 0:
                freed = max(freed, f.size)
                fails, err = 0, ""
            elif not listed:
                fails, err = 1, (e.strip() or "Finder could not empty the Trash")
        return freed, fails, err


def execute(ctx: Ctx, findings: List[Finding], dry_run: bool, assume_yes: bool = False,
            force_running: bool = False, allow_sudo: bool = True) -> Tuple[int, int]:
    todo = [f for f in findings if f.status not in ("done",) and f.action != ACT_NONE]
    if not todo:
        print(c("  Nothing to do.", DIM))
        return 0, 0
    ctx.refresh_running()
    for f in todo:
        f.running = ctx.running(*f.owners) if f.owners else ""
    busy = [f for f in todo if f.running]
    if busy and not force_running:
        names = sorted({f.running for f in busy})
        print(c("  ⚠ %d item(s) belong to apps that are running: %s" % (len(busy), ", ".join(names)), YELLOW))
        skip = True
        if not assume_yes and sys.stdin.isatty():
            skip = ask("  Skip them for now (recommended — or quit those apps first)? [Y/n] ", default=True)
        if skip:
            for f in busy:
                f.status, f.note = "skipped", "%s is running" % f.running
            todo = [f for f in todo if not f.running]
    sudo_items = [f for f in todo if f.sudo]
    if sudo_items and not dry_run and not IS_ROOT:
        if not allow_sudo or not ensure_sudo(interactive=not assume_yes):
            print(c("  Skipping %d item(s) that need administrator rights%s." %
                    (len(sudo_items), "" if allow_sudo else " (use --sudo)"), YELLOW))
            for f in sudo_items:
                f.status, f.note = "skipped", "needs administrator rights"
            todo = [f for f in todo if not f.sudo]
    order = {ACT_EMPTY_TRASH: 0, ACT_DELETE: 1, ACT_CONTENTS: 1, ACT_LAUNCHD: 1, ACT_TRASH: 2, ACT_CMD: 3}
    todo.sort(key=lambda f: order.get(f.action, 9))
    ex = Executor(ctx, dry_run)
    df0, _ = disk_free()
    total = 0
    trashed = 0
    print()
    for i, f in enumerate(todo, 1):
        label = trunc(f.title, term_width() - 34)
        sys.stdout.write("  [%d/%d] %s  " % (i, len(todo), label))
        sys.stdout.flush()
        if f.action == ACT_CMD and not dry_run:
            print()
        try:
            fr = ex.run_one(f)
        except KeyboardInterrupt:
            print(c("interrupted", RED))
            raise
        except Exception as e:  # never crash mid-clean
            f.status, f.note = "failed", str(e)
            LOG.write("ERROR", "%s: %r" % (f.title, e))
            fr = 0
        if f.action == ACT_TRASH and f.status in ("done", "partial"):
            trashed += fr
        else:
            total += fr
        if f.status == "dry":
            print(c("would free %s" % human(fr), CYAN))
        elif f.status == "done":
            print(c("✓ %s%s" % (human(fr), " → Trash" if f.action == ACT_TRASH else ""), GREEN))
        elif f.status == "partial":
            print(c("◐ %s (%s)" % (human(fr), f.note), YELLOW))
        else:
            print(c("✗ %s" % (f.note or f.status), RED))
    du_clear()
    df1, _ = disk_free()
    print()
    if dry_run:
        print(c("  DRY-RUN: nothing was changed. Would free about %s." % human(total + trashed), CYAN, BOLD))
    else:
        print(c("  Freed about %s" % human(total), GREEN, BOLD) +
              (c("  ·  %s moved to Trash (empty it to free that space)" % human(trashed), YELLOW) if trashed else ""))
        print(c("  Free disk space: %s → %s" % (human(df0), human(df1)), DIM))
        print(c("  Log: %s" % short(LOG_FILE), DIM))
    return total, trashed

# =============================================================================
# Interactive UI
# =============================================================================


def ask(prompt: str, default: bool = False) -> bool:
    try:
        a = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if not a:
        return default
    return a in ("y", "yes")


def prompt(text: str) -> str:
    try:
        return input(text).strip()
    except EOFError:
        return "q"
    except KeyboardInterrupt:
        print()
        return ""


def parse_selection(s: str, n: int) -> Optional[List[int]]:
    out: List[int] = []
    for part in re.split(r"[,\s]+", s.strip()):
        if not part:
            continue
        m = re.match(r"^(\d+)-(\d+)$", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                a, b = b, a
            out.extend(range(a, b + 1))
        elif part.isdigit():
            out.append(int(part))
        else:
            return None
    if not out or any(i < 1 or i > n for i in out):
        return None
    seen = set()
    return [i for i in out if not (i in seen or seen.add(i))]


def unique_size(fs: List[Finding]) -> int:
    seen: Set[str] = set()
    total = 0
    for f in fs:
        if f.paths and f.action != ACT_CMD:
            for p in f.paths:
                if p not in seen:
                    seen.add(p)
                    total += du(p)
        else:
            total += f.size
    return total


def tag(f: Finding) -> str:
    if f.status == "done":
        return c("✓ CLEANED     ", GREEN, DIM)
    if f.status == "partial":
        return c("◐ PARTLY DONE ", YELLOW)
    if f.status == "dry":
        return c("~ DRY-RUN     ", CYAN)
    if f.status in ("failed", "skipped"):
        return c("✗ %-12s" % f.status.upper(), RED)
    t, col = REC_STYLE[f.rec]
    return c(t, col, BOLD)


def print_finding(i: int, f: Finding, verbose: bool = False):
    w = term_width()
    size = human(f.size) if (f.size or f.action not in (ACT_CMD, ACT_NONE)) else "—"
    title = trunc(f.title, w - 34)
    print("  %s %s  %s%s" % (c("%3d." % i, BOLD), tag(f), title, " " * max(1, w - 34 - len(title)) + c(size.rjust(9), BOLD)))
    loc = f.where()
    extra = ""
    if f.paths and len(f.paths) > 1:
        extra = "  (%d items)" % len(f.paths)
    if loc:
        print(c("        %s%s" % (trunc(short(loc), w - 20), extra), DIM))
    print("        " + c("Why: ", BOLD) + trunc(f.reason, (w - 14) * (3 if verbose else 2)))
    if f.impact:
        print("        " + c("After: ", BOLD) + c(trunc(f.impact, (w - 16) * 2), DIM))
    flags = []
    if f.action == ACT_TRASH:
        flags.append("goes to Trash")
    if f.sudo:
        flags.append("needs admin password")
    if f.running:
        flags.append(c("⚠ %s is running — quit it first" % f.running, YELLOW))
    if f.note:
        flags.append(c(f.note, YELLOW))
    if flags:
        print("        " + c(" · ", DIM).join(flags))
    if verbose:
        for p in f.paths[:60]:
            print(c("          - %s  %s" % (short(p), human(du(p))), DIM))
        if len(f.paths) > 60:
            print(c("          … and %d more" % (len(f.paths) - 60), DIM))
        for cmd in f.cmds:
            print(c("          $ %s%s" % ("sudo " if f.sudo else "", " ".join(cmd)), DIM))


def header(ctx: Ctx, dry_run: bool):
    w = term_width()
    free, total = disk_free()
    used_pct = (100.0 * (total - free) / total) if total else 0
    print()
    print(c("═" * w, CYAN))
    left = "  clean_mac %s — Ultimate macOS Cleaner" % VERSION
    right = ("DRY-RUN ON" if dry_run else "") + "  "
    print(c(left, BOLD) + " " * max(1, w - len(left) - len(right)) + c(right, YELLOW, BOLD))
    print(c("═" * w, CYAN))
    print("  Disk: %s free of %s (%.0f%% used)    Full Disk Access: %s" % (
        c(human(free), GREEN, BOLD), human(total), used_pct,
        c("yes", GREEN) if ctx.fda else c("NO — some areas can't be fully cleaned", YELLOW)))
    print(c("  Running apps are protected · personal files go to the Trash · every action is logged", DIM))
    if not ctx.fda:
        print(c("  Tip: System Settings ▸ Privacy & Security ▸ Full Disk Access ▸ enable your terminal app.", YELLOW))
    for wmsg in ctx.warnings:
        print(c("  ! " + wmsg, YELLOW))


def dashboard(ctx: Ctx, res: Dict[str, List[Finding]], dry_run: bool):
    header(ctx, dry_run)
    w = term_width()
    print()
    print(c("   #  %-40s %12s %12s %7s" % ("Area", "Recommended", "Review", "Items"), BOLD))
    tot_r: List[Finding] = []
    tot_v: List[Finding] = []
    n_all = 0
    for i, (key, title, _) in enumerate(AREAS, 1):
        fs = [f for f in res.get(key, []) if f.status != "done"]
        r = [f for f in fs if f.rec == REC]
        v = [f for f in fs if f.rec == REV]
        tot_r += r
        tot_v += v
        n_all += len(fs)
        rs = unique_size(r)
        vs = unique_size(v)
        line = "  %2d  %-40s %12s %12s %7s" % (i, trunc(title, 40), human(rs) if r else "—", human(vs) if v else "—",
                                               len(fs) or "·")
        print(c(line, DIM) if not fs else line)
    print(c("  " + "─" * (w - 4), DIM))
    print(c("      %-40s %12s %12s %7d" % ("TOTAL", human(unique_size(tot_r)), human(unique_size(tot_v)), n_all), BOLD))
    print()
    print("  %s open an area   %s smart-clean all RECOMMENDED   %s full report   %s export JSON" % (
        c("[1-%d]" % len(AREAS), BOLD), c("S", BOLD, GREEN), c("F", BOLD), c("E", BOLD)))
    print("  %s toggle dry-run   %s ignore list   %s re-scan   %s quit" % (
        c("D", BOLD), c("W", BOLD), c("R", BOLD), c("Q", BOLD)))


def area_view(ctx: Ctx, res: Dict[str, List[Finding]], key: str, state: Dict[str, bool]):
    while True:
        fs = res.get(key, [])
        idx = [k for k, _, _ in AREAS].index(key) + 1
        print()
        print(c("── %d. %s ── %s" % (idx, AREA_TITLE[key], AREA_DESC[key]), BOLD, CYAN))
        if not fs:
            print(c("  Nothing found here — this area is clean. ✔", GREEN))
            prompt("\n  Press Enter to go back… ")
            return
        for i, f in enumerate(fs, 1):
            print_finding(i, f)
        rec = [f for f in fs if f.rec == REC and f.status != "done"]
        print()
        print("  %s clean RECOMMENDED (%s)   %s clean RECOMMENDED + REVIEW   %s clean selected" % (
            c("r", BOLD, GREEN), human(unique_size(rec)), c("a", BOLD), c("1,3-5", BOLD)))
        print("  %s details   %s reveal in Finder   %s always ignore   %s back%s" % (
            c("i N", BOLD), c("o N", BOLD), c("x N", BOLD), c("b", BOLD),
            c("   (dry-run ON)", YELLOW) if state["dry"] else ""))
        ch = prompt("\n  > ").strip()
        low = ch.lower()
        if low in ("b", "back", "", "q"):
            return
        if low == "r":
            if rec and ask("  Clean %d RECOMMENDED item(s), about %s? [y/N] " % (len(rec), human(unique_size(rec)))):
                execute(ctx, rec, state["dry"])
                prompt("\n  Press Enter to continue… ")
            continue
        if low == "a":
            sel = [f for f in fs if f.rec in (REC, REV) and f.status != "done"]
            n_rev = len([f for f in sel if f.rec == REV])
            if sel and ask("  Clean %d item(s) incl. %d REVIEW item(s), about %s? [y/N] " %
                           (len(sel), n_rev, human(unique_size(sel)))):
                execute(ctx, sel, state["dry"])
                prompt("\n  Press Enter to continue… ")
            continue
        m = re.match(r"^([iox])\s*(\d+)$", low)
        if m:
            n = int(m.group(2))
            if not 1 <= n <= len(fs):
                print(c("  No item %d." % n, RED))
                continue
            f = fs[n - 1]
            if m.group(1) == "i":
                print()
                print_finding(n, f, verbose=True)
                prompt("\n  Press Enter to continue… ")
            elif m.group(1) == "o":
                target = f.location or (f.paths[0] if f.paths else "")
                if target and os.path.exists(target):
                    run(user_cmd(["open", "-R", target]), 10)
                else:
                    print(c("  Nothing to reveal.", YELLOW))
            else:
                entry = f.location or (f.paths[0] if len(f.paths) == 1 else "")
                if not entry:
                    print(c("  This item has no single path to ignore; add it manually with W.", YELLOW))
                    continue
                if add_ignore(entry):
                    ctx.ignore = load_ignore()
                    res[key] = [x for x in fs if x is not f]
                    print(c("  Added %s to the ignore list." % short(entry), GREEN))
            continue
        sel_idx = parse_selection(ch, len(fs))
        if sel_idx is None:
            print(c("  Didn't understand that. Use r, a, numbers like 1,3-5, i N, o N, x N or b.", RED))
            continue
        sel = [fs[i - 1] for i in sel_idx]
        keep = [f for f in sel if f.rec == KEEP]
        if keep:
            print(c("  ⚠ %d selected item(s) are marked KEEP:" % len(keep), YELLOW, BOLD))
            for f in keep:
                print(c("     - %s: %s" % (f.title, f.impact or f.reason), YELLOW))
            if prompt("  Type 'yes' to include them anyway: ").lower() != "yes":
                sel = [f for f in sel if f.rec != KEEP]
        if sel and ask("  Clean %d selected item(s), about %s? [y/N] " % (len(sel), human(unique_size(sel)))):
            execute(ctx, sel, state["dry"])
            prompt("\n  Press Enter to continue… ")


def full_report(res: Dict[str, List[Finding]], areas: Optional[Set[str]] = None):
    for i, (key, title, desc) in enumerate(AREAS, 1):
        if areas is not None and key not in areas:
            continue
        fs = res.get(key, [])
        print()
        print(c("── %d. %s ── %s" % (i, title, desc), BOLD, CYAN))
        if not fs:
            print(c("  ✔ Nothing found — clean.", GREEN))
            continue
        for j_, f in enumerate(fs, 1):
            print_finding(j_, f)


def export_json(res: Dict[str, List[Finding]], path: str) -> bool:
    data = {"version": VERSION, "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "areas": {}}
    for key, title, _ in AREAS:
        data["areas"][key] = {"title": title, "findings": [{
            "title": f.title, "recommendation": f.rec, "reason": f.reason, "impact": f.impact,
            "size": f.size, "size_human": human(f.size), "action": f.action, "sudo": f.sudo,
            "running": f.running, "location": f.location, "paths": f.paths, "commands": f.cmds,
            "status": f.status} for f in res.get(key, [])]}
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        return True
    except OSError as e:
        print(c("  Could not write %s: %s" % (path, e), RED))
        return False


def ignore_menu(ctx: Ctx):
    print()
    print(c("── Ignore list ── %s" % short(IGNORE_FILE), BOLD, CYAN))
    pats = load_ignore()
    if pats:
        for i, p in enumerate(pats, 1):
            print("  %2d. %s" % (i, p))
    else:
        print(c("  (empty) — paths, globs (*.zip) or keywords listed here are never touched.", DIM))
    print("\n  1 add an entry   2 open the file in an editor   b back")
    ch = prompt("  > ").lower()
    if ch == "1":
        e = prompt("  Path, glob or keyword: ")
        if e and add_ignore(e):
            print(c("  Added.", GREEN))
    elif ch == "2":
        if not os.path.exists(IGNORE_FILE):
            add_ignore("# example: ~/Downloads/keep-me.dmg")
        run(user_cmd(["open", "-t", IGNORE_FILE]), 10)
    ctx.ignore = load_ignore()


def interactive(opts):
    state = {"dry": bool(opts.dry_run)}
    ctx = Ctx(opts)
    res = scan_all(ctx)
    while True:
        dashboard(ctx, res, state["dry"])
        ch = prompt("\n  > ").lower()
        if ch in ("q", "quit", "exit", "0"):
            print(c("\n  Bye — your Mac is cleaner. ✨\n", GREEN))
            return
        if ch.isdigit() and 1 <= int(ch) <= len(AREAS):
            area_view(ctx, res, AREAS[int(ch) - 1][0], state)
        elif ch == "s":
            rec = [f for k in res for f in res[k] if f.rec == REC and f.status != "done"]
            if not rec:
                print(c("  No RECOMMENDED items left.", GREEN))
                continue
            print()
            print(c("  Smart Clean will process every RECOMMENDED item:", BOLD))
            for key, title, _ in AREAS:
                r = [f for f in res[key] if f.rec == REC and f.status != "done"]
                if r:
                    print("    %-40s %3d item(s)  %10s" % (title, len(r), human(unique_size(r))))
            print(c("    REVIEW and KEEP items are not touched. Running apps' items are skipped.", DIM))
            if ask("\n  Proceed with Smart Clean (about %s)? [y/N] " % human(unique_size(rec))):
                execute(ctx, rec, state["dry"])
                prompt("\n  Press Enter to continue… ")
        elif ch == "f":
            full_report(res)
            prompt("\n  Press Enter to continue… ")
        elif ch == "e":
            path = os.path.join(LOG_DIR, "report-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
            if export_json(res, path):
                print(c("  Report saved to %s" % short(path), GREEN))
        elif ch == "d":
            state["dry"] = not state["dry"]
            print(c("  Dry-run is now %s." % ("ON — nothing will be changed" if state["dry"] else "OFF"), YELLOW))
        elif ch == "w":
            ignore_menu(ctx)
        elif ch == "r":
            du_clear()
            ctx = Ctx(opts)
            res = scan_all(ctx)
        elif ch:
            print(c("  Unknown choice.", RED))

# =============================================================================
# Entry point
# =============================================================================


def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(prog="clean_mac", description="Ultimate macOS cleaner (v%s)" % VERSION,
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Areas: " + ", ".join(k for k, _, _ in AREAS))
    ap.add_argument("--scan", "--report", action="store_true", help="print the full report and exit (no changes)")
    ap.add_argument("--clean", choices=["recommended", "all"], help="clean non-interactively")
    ap.add_argument("--area", help="comma-separated list of areas to include")
    ap.add_argument("--dry-run", action="store_true", help="simulate; change nothing")
    ap.add_argument("-y", "--yes", action="store_true", help="don't ask for confirmation")
    ap.add_argument("--sudo", action="store_true", help="include admin-level items when cleaning non-interactively")
    ap.add_argument("--force-running", action="store_true", help="also clean items of running apps")
    ap.add_argument("--large-mb", type=int, default=200, help="large-file threshold in MB (default 200)")
    ap.add_argument("--dupe-mb", type=float, default=1.0, help="minimum size for duplicate detection in MB (default 1)")
    ap.add_argument("--old-days", type=int, default=90, help="age for 'old download' (default 90 days)")
    ap.add_argument("--unused-days", type=int, default=120, help="age for 'unused app' (default 120 days)")
    ap.add_argument("--json", metavar="FILE", help="write the report as JSON")
    ap.add_argument("--list-areas", action="store_true", help="list area keys and exit")
    ap.add_argument("--no-color", action="store_true", help="disable colours")
    ap.add_argument("--version", action="version", version="clean_mac %s" % VERSION)
    # v2 compatibility flags
    ap.add_argument("--all-safe", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--old-versions", "-u", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--cat2", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--cat3", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--empty-trash", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--thin-snapshots", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--broken-symlinks", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--large-files", nargs="?", const=200, type=int, help=argparse.SUPPRESS)
    opts = ap.parse_args()
    if opts.no_color:
        USE_COLOR = False
    if opts.list_areas:
        for k, t, d in AREAS:
            print("  %-10s %-36s %s" % (k, t, d))
        return 0
    if sys.platform != "darwin":
        print("clean_mac only runs on macOS.")
        return 1
    legacy = None
    if opts.all_safe:
        opts.clean = "recommended"
    for flag, area, mode in ((opts.old_versions, "updates", "recommended"), (opts.cat2, "leftovers", "recommended"),
                             (opts.cat3, "caches", "recommended"), (opts.empty_trash, "trash", "recommended"),
                             (opts.thin_snapshots, "snapshots", "all"), (opts.broken_symlinks, "clutter", "recommended")):
        if flag:
            legacy = area
            opts.area = area
            opts.clean = opts.clean or mode
    if opts.large_files is not None:
        opts.large_mb = opts.large_files
        opts.area = "large"
        opts.scan = True
    areas: Optional[Set[str]] = None
    if opts.area:
        areas = {a.strip().lower() for a in opts.area.split(",") if a.strip()}
        bad = areas - set(AREA_TITLE)
        if bad:
            print("Unknown area(s): %s. Use --list-areas." % ", ".join(sorted(bad)))
            return 2
    interactive_mode = not (opts.scan or opts.clean or opts.json) and sys.stdin.isatty()
    if interactive_mode and areas is None:
        interactive(opts)
        return 0
    ctx = Ctx(opts)
    res = scan_all(ctx, areas)
    if opts.json:
        if export_json(res, opts.json):
            print("Report written to %s" % opts.json)
    if opts.scan or not opts.clean:
        header(ctx, opts.dry_run)
        full_report(res, areas)
        allf = [f for k in res for f in res[k]]
        print()
        print(c("  RECOMMENDED: %s   ·   REVIEW: %s   ·   items: %d" % (
            human(unique_size([f for f in allf if f.rec == REC])),
            human(unique_size([f for f in allf if f.rec == REV])), len(allf)), BOLD))
        if not opts.clean:
            return 0
    wanted = (REC,) if opts.clean == "recommended" else (REC, REV)
    sel = [f for k in res for f in res[k] if f.rec in wanted]
    if legacy == "snapshots":
        sel = [f for f in res["snapshots"]]
    if not sel:
        print(c("Nothing to clean. ✔", GREEN))
        return 0
    print(c("\n  %d item(s), about %s, will be cleaned%s." % (len(sel), human(unique_size(sel)),
                                                             " (DRY-RUN)" if opts.dry_run else ""), BOLD))
    if not opts.yes and not opts.dry_run:
        if not sys.stdin.isatty():
            print("Refusing to clean without confirmation in a non-interactive shell; add --yes.")
            return 2
        if not ask("  Proceed? [y/N] "):
            return 0
    execute(ctx, sel, opts.dry_run, assume_yes=opts.yes, force_running=opts.force_running,
            allow_sudo=opts.sudo or IS_ROOT or (sys.stdin.isatty() and not opts.yes))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(c("\n  Interrupted — nothing more was changed.", YELLOW))
        sys.exit(130)
