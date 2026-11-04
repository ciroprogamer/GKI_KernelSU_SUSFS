#!/usr/bin/env python3
"""Make SUSFS's sus-type lookup compare the type value, not the hash bucket.

susfs4ksu 83b341e ("Refactor selinux_hide") added SUS_TYPE_HLIST, a 1024-bucket
hashtable of the SELinux types KernelSU (and modules) add to the policy. Its
entries carry no key:

    struct st_susfs_sus_type_hlist { struct hlist_node node; };

    hash_for_each_possible_rcu(SUS_TYPE_HLIST, entry, node, type_value)
        return true;

so susfs_is_sus_type_rcu() answers "true" for every type that merely hashes into
a bucket holding a sus type. With selinux_hide running, the setprocattr("current")
path for uid >= 10000 then rejects that stock type with -EINVAL; if the colliding
type is an app domain (untrusted_app*, priv_app, platform_app, ...), zygote's
setcon fails and none of those apps start. susfs_add_sus_type() has the mirror
bug: a second sus type in an occupied bucket is refused as a duplicate.

Store the type value in the entry and compare it on both paths.

usage: susfs_sus_type_exact_match.py <path/to/fs/susfs.c>
Exit 0 when patched or nothing to patch; 1 when the code shape is unexpected.
"""

import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    path = sys.argv[1]
    src = open(path, encoding="utf-8").read()

    struct_re = re.compile(
        r"(struct st_susfs_sus_type_hlist \{\n)(.*?)(\n\};)", re.S)
    m = struct_re.search(src)
    if not m:
        print(f"  {path}: no SUS_TYPE_HLIST (older susfs); nothing to do")
        return 0
    if "type_value" in m.group(2):
        print(f"  {path}: sus-type entries already carry their type value")
        return 0

    def sub_once(pattern, repl, what, flags=0):
        nonlocal src
        new, n = re.subn(pattern, repl, src, count=0, flags=flags)
        if n != 1:
            print(f"ERROR: {what}: expected 1 match, found {n} in {path}",
                  file=sys.stderr)
            sys.exit(1)
        src = new

    # 1. the entry remembers which type it is
    sub_once(r"(struct st_susfs_sus_type_hlist \{\n\s*struct hlist_node\s+node;\n)",
             r"\1\tu32                                     type_value;\n",
             "struct st_susfs_sus_type_hlist")

    # 2. duplicate check in susfs_add_sus_type(): same value, not same bucket
    sub_once(r"(hash_for_each_possible_safe\(SUS_TYPE_HLIST, (\w+), \w+, node, type_value\) \{\n)",
             r"\1\t\tif (\2->type_value != type_value)\n\t\t\tcontinue;\n",
             "duplicate loop in susfs_add_sus_type")

    # 3. record the value before publishing the entry
    sub_once(r"(\n(\s*)hash_add_rcu\(SUS_TYPE_HLIST, &(\w+)->node, type_value\);)",
             r"\n\2\3->type_value = type_value;\1",
             "hash_add_rcu in susfs_add_sus_type")

    # 4. lookup: a hit is an equal value, not a non-empty bucket
    sub_once(r"(hash_for_each_possible_rcu\(SUS_TYPE_HLIST, (\w+), node, type_value\) \{\n)(\s*)return true;",
             r"\1\3if (\2->type_value == type_value)\n\3\treturn true;",
             "lookup loop in susfs_is_sus_type_rcu")

    open(path, "w", encoding="utf-8").write(src)
    print(f"  {path}: sus-type lookup now matches the exact type value")
    return 0


if __name__ == "__main__":
    sys.exit(main())
