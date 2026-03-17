// Auto-Complete Support:
// Type modulename. followed by a CTRL + SPACE
// Yara documentation: https://yara.readthedocs.io/en/stable/writingrules.html

import "hash"

rule find_by_hash
{
    meta:
        description = "Find files by hash."

    condition:
        hash.sha256(0, filesize) == "b6800c2ca4bfec26c8b8553beee774f4ebab741b1a48adcccce79f07062977be"
}