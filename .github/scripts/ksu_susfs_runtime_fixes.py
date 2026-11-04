#!/usr/bin/env python3
"""Runtime fixes for a root implementation's SUSFS-era kernel code.

Each fix is independent, idempotent, and a no-op when its pattern is absent
(another root, or upstream already fixed it). Found by review of pershoot's
KernelSU-Next dev-susfs (83349468, 2026-11-04):

1. feature/sucompat.c - credential reference leak on every execve.
   `is_init(get_current_cred())` takes a reference that is never dropped, so
   each exec through the su-compat hook pins the old struct cred (and its
   SELinux blob and user/group refs) forever. is_init() only reads it:
   current_cred() is the right accessor.

2. manager/throne_tracker.c - threaded tracker can disable itself until reboot.
   track_throne() reserves the slot with a sentinel, kthread_run()s the scan,
   then unconditionally stores the task pointer. If the thread already ran to
   completion and cleared the slot, that store leaves a dead task in it and
   every later cmpxchg(NULL, ...) fails: manager installs and uid changes are
   ignored until reboot. Store only over the sentinel.

3. manager/pkg_observer.c - SUSFS priority uid filter never refreshed.
   The filter's package names are re-resolved after packages.list changes only
   in the non-threaded tracker path; with the default
   CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED=y a reinstalled app's new uid is
   never filtered. Add the same refresh to the threaded branch (it only
   kthread_run()s a single-flight worker, as track_throne() already does there).

usage: ksu_susfs_runtime_fixes.py <root>/kernel
Exit 0 when every fix applied or was not applicable; 1 on an unexpected shape.
"""

import os
import re
import sys

FAILED = False


def edit(path, fix):
    global FAILED
    if not os.path.exists(path):
        print(f"  {path}: not present; skipped")
        return
    src = open(path, encoding="utf-8").read()
    new, msg, ok = fix(src)
    if not ok:
        FAILED = True
        print(f"ERROR: {path}: {msg}", file=sys.stderr)
        return
    if new != src:
        open(path, "w", encoding="utf-8").write(new)
    print(f"  {path}: {msg}")


def fix_cred_leak(src):
    pattern = "is_init(get_current_cred())"
    n = src.count(pattern)
    if n == 0:
        return src, "no get_current_cred() leak", True
    return src.replace(pattern, "is_init(current_cred())"), \
        f"is_init(get_current_cred()) -> current_cred() ({n} site(s))", True


THRONE_STORE = re.compile(
    r"(\tif \(IS_ERR\(t\)\)\n\t\tWRITE_ONCE\(throne_thread, NULL\);\n\telse\n)"
    r"\t\tWRITE_ONCE\(throne_thread, t\);\n")


def fix_throne_race(src):
    if "throne_thread" not in src or "CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED" not in src:
        return src, "no threaded throne tracker", True
    if "CI: store only over the sentinel" in src:
        return src, "sentinel-guarded store already present", True
    if len(THRONE_STORE.findall(src)) != 1:
        if "WRITE_ONCE(throne_thread, t);" not in src:
            return src, "no unconditional task store; nothing to do", True
        return src, "threaded launch block has an unexpected shape", False
    new = THRONE_STORE.sub(
        r"\1"
        "\t\t/* CI: store only over the sentinel - a scan that already\n"
        "\t\t * finished has reset the slot to NULL and must stay that way */\n"
        "\t\tcmpxchg(&throne_thread,\n"
        "\t\t\t(struct task_struct *)ERR_PTR(-EINPROGRESS), t);\n",
        src, count=1)
    return new, "threaded launch stores the task only over its sentinel", True


PKG_ANCHOR = re.compile(
    r"(#ifdef CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED\n(\s*)track_throne\(false\);\n)(#else\n)")


def fix_priority_refresh(src):
    if "susfs_parse_priority_app_strings" not in src:
        return src, "no priority uid filter refresh in this root", True
    if "CI: renew the priority uid bitmap filter in threaded mode" in src:
        return src, "threaded refresh already present", True
    found = PKG_ANCHOR.findall(src)
    if not found:
        block = re.search(r"#ifdef CONFIG_KSU_THRONE_TRACKER_ALWAYS_THREADED\n(.*?)#else", src, re.S)
        if block and "susfs_parse_priority_app_strings" in block.group(1):
            return src, "upstream already refreshes in threaded mode", True
        return src, "threaded track_throne(false) branch not found", False
    if len(found) != 1:
        return src, f"{len(found)} threaded branches, expected 1", False
    new = PKG_ANCHOR.sub(
        lambda m: m.group(1)
        + "#ifdef CONFIG_KSU_SUSFS_PRIORITY_UID_FILTER\n"
        + f"{m.group(2)}// CI: renew the priority uid bitmap filter in threaded mode too\n"
        + f"{m.group(2)}susfs_parse_priority_app_strings();\n"
        + "#endif\n"
        + m.group(3),
        src, count=1)
    return new, "priority uid filter now refreshes in threaded mode", True


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: ksu_susfs_runtime_fixes.py <root>/kernel", file=sys.stderr)
        return 2
    kdir = sys.argv[1]
    edit(os.path.join(kdir, "feature/sucompat.c"), fix_cred_leak)
    edit(os.path.join(kdir, "manager/throne_tracker.c"), fix_throne_race)
    edit(os.path.join(kdir, "manager/pkg_observer.c"), fix_priority_refresh)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
