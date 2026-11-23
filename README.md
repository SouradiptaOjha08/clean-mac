<div align="center">

```
      _                                                
  ___| | ___  __ _ _ __        _ __ ___   __ _  ___ 
 / __| |/ _ \/ _` | '_ \      | '_ ` _ \ / _` |/ __|
| (__| |  __/ (_| | | | |     | | | | | | (_| | (__ 
 \___|_|\___|\__,_|_| |_|_____|_| |_| |_|\__,_|\___|
                        |_____|                     
```

### 🧹 The no-nonsense, open-source deep cleaner for macOS

**22 areas scanned · a clear recommendation for every item · nothing deleted without your OK**

![macOS](https://img.shields.io/badge/macOS-12%2B-000000?logo=apple&logoColor=white)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Status](https://img.shields.io/badge/status-public%20beta-orange)
![License](https://img.shields.io/badge/license-MIT-blue)

[Quick start](#-quick-start) · [What it cleans](#-what-it-cleans-22-areas) · [Safety](#-safety-first) · [Usage](#-usage) · [Limitations](#-honest-limitations) · [Testing feedback](#-help-test-it)

</div>

---

## ✨ Why clean_mac?

Most cleaners either delete a fixed list of folders blindly, or hide what they do behind a big "Clean" button.
**clean_mac shows you everything it finds, tells you *why* it is junk, what happens after you remove it — and lets you decide.**

| | |
|---|---|
| 🔍 **Finds what others miss** | Detects leftovers of *any* uninstalled app by matching your Library against what is actually installed — not a hard-coded list. |
| 🏷️ **A verdict for every item** | Each finding is tagged **✔ RECOMMENDED**, **? REVIEW** or **■ KEEP**, with a reason and an "after" note. |
| 🛡️ **Safe by design** | Protected locations, no symlink following, personal files go to the Trash, running apps are skipped, everything is logged. |
| 🧑‍💻 **Built for developers too** | node_modules, venvs, build outputs, Gradle/Maven/npm/pip/Go/Cargo caches, Docker, Xcode, JetBrains, VS Code, Jenkins … |
| 📦 **Zero dependencies** | One Python file using only the standard library. No installer, no background daemon, no telemetry. |

---

## 🖥️ What it looks like

```
══════════════════════════════════════════════════════════════════════════════════
  clean_mac 3.0 — Ultimate macOS Cleaner
══════════════════════════════════════════════════════════════════════════════════
  Disk: 133.7 GB free of 245.1 GB (45% used)    Full Disk Access: yes
  Running apps are protected · personal files go to the Trash · every action is logged

   #  Area                                      Recommended       Review   Items
   1  Trash                                               —            —       ·
   2  System & User Caches                          62.5 MB            —       5
   3  Logs & Crash Reports                           5.8 MB            —       4
   5  Browsers                                     263.6 MB       7.9 MB       4
   6  App Internal Caches                          298.4 MB      40.0 MB       9
   7  Old Versions & Update Leftovers              522.1 MB      13.6 MB       4
   8  Uninstalled App Leftovers                           —     516.9 MB       4
  11  Code Editors                                   1.3 GB            —       2
  12  Developer Tools & Package Caches             501.0 MB     368.1 MB      16
  …
  ────────────────────────────────────────────────────────────────────────────────
      TOTAL                                          3.0 GB       1.9 GB     136

  [1-22] open an area   S smart-clean all RECOMMENDED   F full report   E export JSON
  D toggle dry-run   W ignore list   R re-scan   Q quit
```

Open an area to see every item with its verdict:

```
── 11. Code Editors ── VS Code family: old extensions, VSIX cache, orphan workspace data
    1. ✔ RECOMMENDED  VS Code — cached extension installers (VSIX)          1.2 GB
        ~/Library/Application Support/Code/CachedExtensionVSIXs  (20 items)
        Why: A copy of every extension package VS Code downloaded. The extensions are
             already installed; these copies are only used to re-install.
        After: Re-installing an extension downloads it again.

── 8. Uninstalled App Leftovers ── Data of apps that are no longer installed
    1. ? REVIEW       Adobe — system-wide app data                          433.6 MB
        /Library/Application Support/Adobe
        Why: No installed app matches 'Adobe'. Not modified for 238 days.
        needs admin password
```

---

## 🚀 Quick start

> **Requirements:** macOS 12 or newer (tested so far on the latest macOS, Apple Silicon) and Python 3.9+ (`python3` ships with Apple's Command Line Tools — run `xcode-select --install` if it's missing).

```bash
# 1. Download
curl -fsSL https://raw.githubusercontent.com/SouradiptaOjha08/clean-mac/main/clean_mac.py -o clean_mac
chmod +x clean_mac

# 2. Look first — this changes nothing
./clean_mac --scan

# 3. Clean interactively
./clean_mac
```

Want it available everywhere? Move it into your `PATH`, e.g. `mkdir -p ~/bin && mv clean_mac ~/bin/`.

<details>
<summary><b>Or clone the repo</b></summary>

```bash
git clone https://github.com/SouradiptaOjha08/clean-mac.git
cd clean-mac
python3 clean_mac.py --scan
```
</details>

> 💡 **Tip:** give your terminal app **Full Disk Access** (System Settings ▸ Privacy & Security ▸ Full Disk Access) so clean_mac can see Safari, Mail downloads and device backups. It works without it — those areas are just skipped.

---

## 🗂️ What it cleans (22 areas)

| # | Area | Highlights |
|:-:|---|---|
| 1 | 🗑️ **Trash** | Your Trash and Trash folders on external volumes |
| 2 | 💾 **System & User Caches** | `~/Library/Caches`, `/Library/Caches`, caches of uninstalled apps |
| 3 | 📜 **Logs & Crash Reports** | App logs, diagnostic/crash reports, rotated `/var/log` archives |
| 4 | ⏳ **Temporary Files** | Stale files in your temp folders (sockets and in-use files are skipped) |
| 5 | 🌐 **Browsers** | Safari, Chrome, Brave, Edge, Firefox, Arc, Opera, Vivaldi, Zen … caches, shader caches, crash dumps, on-device AI models, profiles of browsers you uninstalled |
| 6 | 📱 **App Internal Caches** | Electron/Chromium app caches (Slack, Notion, Claude, Spotify …) and sandboxed app caches |
| 7 | ♻️ **Old Versions & Update Leftovers** | Previous app versions behind `current` links, old JetBrains/Android Studio folders, Sparkle/Squirrel/electron-updater payloads, Homebrew cleanup & autoremove, duplicate `.app` copies, macOS installers |
| 8 | 👻 **Uninstalled App Leftovers** | App Support, Containers, Group Containers, Preferences, Saved State, WebKit, HTTP storage, `/Library/Application Support`, `/Users/Shared`, forgotten `~/.tool` folders |
| 9 | 🚦 **Startup Items, Plug-ins & Receipts** | Broken or orphaned LaunchAgents/Daemons, privileged helpers, audio drivers, prefPanes, QuickLook/Spotlight plug-ins, installer receipts of removed packages |
| 10 | 💤 **Unused Applications** | Apps you haven't opened in 120+ days |
| 11 | 🧩 **Code Editors** | VS Code, Cursor, Windsurf, VSCodium, Antigravity …: VSIX cache, old extension versions, state of deleted projects, data of removed extensions |
| 12 | 🛠️ **Developer Tools & Package Caches** | npm, Yarn, pnpm, Bun, pip, Poetry, uv, Conda, Go, Cargo, CocoaPods, Maven, Gradle, Android, Flutter, NVM/pyenv/SDKMAN versions, JetBrains indexes, Jenkins, AI model caches, `~/.cache` |
| 13 | 📁 **Project Junk** | `node_modules`, Python venvs, `target/`, `build/`, `.gradle`, `.next`, `__pycache__`, pytest/mypy/ruff caches — rated by how long the project has been untouched |
| 14 | 🐳 **Docker / Colima** | Stopped containers, dangling/unused images, build cache, unused volumes, VM trim |
| 15 | 🔨 **Xcode & Simulators** | DerivedData, old DeviceSupport, unavailable simulators, previews, archives |
| 16 | 🍎 **Apple Apps & Devices** | iPhone/iPad backups, `.ipsw` firmware, Mail attachment downloads, Aerial videos, GarageBand libraries |
| 17 | ⬇️ **Downloads Folder** | Used installers (`.dmg`/`.pkg`), already-extracted archives, app copies, incomplete and old downloads |
| 18 | 🐘 **Large Files** | The biggest files in your home folder |
| 19 | 👯 **Duplicate Files** | Byte-identical files (SHA-1 verified); project folders and code libraries are excluded |
| 20 | 🧽 **Clutter** | `.DS_Store`, `._` files, Office `~$` files, broken symlinks, empty folders, old screenshots |
| 21 | 📸 **APFS Local Snapshots** | Time Machine local snapshots holding "purgeable" space |
| 22 | 🔧 **Maintenance Tasks** | Quick Look reset, LaunchServices cleanup, DNS flush, font caches, purge, Spotlight rebuild, Login Items |

---

## 🏷️ How to read the verdicts

| Verdict | Meaning | Smart Clean touches it? |
|---|---|:-:|
| ✔ **RECOMMENDED** | Regenerated automatically or pure junk. Safe to remove. | ✅ |
| ? **REVIEW** | Probably not needed, but it's your data or your choice (e.g. old downloads, leftovers, duplicates, Docker volumes). | ❌ only if you pick it |
| ■ **KEEP** | Shown for information (e.g. Photos library, Colima VM). Removing needs you to type `yes`. | ❌ |

Every item also says **Why** it was flagged and what happens **After** you remove it.

---

## 🛡️ Safety first

- 🔒 **Hard-protected locations** can never be deleted — keychains, iCloud Drive, Mail, Messages, Photos libraries, `~/.ssh`, `~/.gnupg`, any `.git` folder, system folders, and the top level of your home folder.
- 🔗 **Symlinks are never followed**, and a symlinked parent can't be used to escape the protected list.
- 🗑️ **Your files go to the Trash**, not oblivion — downloads, large files, duplicates, apps and leftovers are recoverable.
- 🏃 **Running apps are respected** — their caches are skipped unless you explicitly allow it.
- 🔑 **Admin items are opt-in** — anything under `/Library` asks for your password; nothing runs as root silently.
- 🧪 **Dry-run mode** (`D` in the menu, or `--dry-run`) shows exactly what would happen.
- 📝 **Everything is logged** to `~/Library/Logs/clean_mac/clean_mac.log`.
- 🙈 **Ignore list** — put paths, globs (`*.zip`) or keywords in `~/.clean_mac_ignore` (or press `x N` on an item) and they are never touched.

---

## 📖 Usage

```bash
clean_mac                               # interactive dashboard
clean_mac --scan                        # full report, changes nothing
clean_mac --clean recommended           # clean every RECOMMENDED item (asks once)
clean_mac --clean all                   # RECOMMENDED + REVIEW items
clean_mac --area caches,logs --scan     # only some areas
clean_mac --dry-run --clean all         # simulate everything
clean_mac --json report.json            # export the findings
clean_mac --list-areas                  # show all area keys
```

<details>
<summary><b>All options</b></summary>

| Option | Description |
|---|---|
| `--scan` / `--report` | Print the full report and exit |
| `--clean recommended\|all` | Clean without the menu |
| `--area a,b,c` | Limit to specific areas (see `--list-areas`) |
| `--dry-run` | Simulate; change nothing |
| `-y`, `--yes` | Don't ask for confirmation |
| `--sudo` | Include admin-level items in non-interactive runs |
| `--force-running` | Also clean items of running apps |
| `--large-mb N` | Large-file threshold (default 200 MB) |
| `--dupe-mb N` | Minimum size for duplicate detection (default 1 MB) |
| `--old-days N` | Age of an "old download" (default 90 days) |
| `--unused-days N` | Age of an "unused app" (default 120 days) |
| `--json FILE` | Write the report as JSON |
| `--no-color` | Plain output |

</details>

<details>
<summary><b>Interactive keys</b></summary>

**Dashboard:** `1-22` open area · `S` Smart Clean (all RECOMMENDED) · `F` full report · `E` export JSON · `D` dry-run · `W` ignore list · `R` re-scan · `Q` quit

**Inside an area:** `r` clean RECOMMENDED · `a` clean RECOMMENDED + REVIEW · `1,3-5` clean selected · `i N` details · `o N` reveal in Finder · `x N` always ignore · `b` back

</details>

---

## 🧠 How it decides

1. **Indexes what's installed** — every app (via Spotlight and the Applications folders), its embedded extensions and helpers, command-line tools in your `PATH`, Homebrew formulae/casks and editor extensions.
2. **Runs specific scanners first** (browsers, editors, Xcode, Docker, dev tools …) that know exactly which sub-folders are cache.
3. **Runs generic scanners afterwards** (caches, app caches, leftovers) that skip anything already handled — so nothing is counted twice.
4. **Compares every Library entry** against the index: Apple-owned → ignored, installed → kept, same vendor → REVIEW, no owner → leftover. Anything modified in the last 1–4 weeks is assumed to be in use.
5. **Re-checks running apps and safety rules** right before anything is removed.

---

## ⚠️ Honest limitations

clean_mac is thorough, but it is **beta software** and it is not magic:

- 🧪 **Tested on one Mac so far** (Apple Silicon, recent macOS, Python 3.9). Intel Macs and older macOS versions *should* work — that's what this public test is for.
- 🔮 **Leftover detection is heuristic.** It matches folder names to installed apps, so it can be wrong — which is why leftovers are always REVIEW, never auto-cleaned.
- 🚫 **Deliberately not done:** stripping language files or unused CPU architectures from apps (breaks code signatures), Time Machine backups on external disks, other user accounts, cleaning *inside* Mail/Messages/Photos (shown as info only).
- 🗺️ **Not yet available:** one-step app uninstaller, Login Items management (it only opens System Settings), similar-photo detection, old simulator runtimes.
- 🌍 Docker images/volumes are only analysed while Docker/Colima is running.

**Always run `--scan` or dry-run first, and keep a backup.** The software is provided as-is under the MIT license.

---

## 🧪 Help test it

This is a public beta — your feedback makes it better. Please [open an issue](https://github.com/SouradiptaOjha08/clean-mac/issues) with:

- your macOS version and chip (`sw_vers -productVersion; uname -m`)
- what went wrong, or what it flagged that it shouldn't have (or missed)
- the relevant lines of `clean_mac --scan` output

> 🔐 Reports and logs contain file paths from your Mac — remove anything private before sharing.

---

## 🗺️ Roadmap

- [ ] One-step app uninstaller (app + all its leftovers)
- [ ] Login Items / background items manager
- [ ] Old Xcode simulator runtimes & old Xcode versions
- [ ] Conda environments & more language toolchains
- [ ] Homebrew install option

---

<div align="center">

Made with ☕ and a strong dislike of junk files · MIT License

⭐ If clean_mac freed some space for you, a star helps others find it!

</div>
