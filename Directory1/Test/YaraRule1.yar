// Auto-Complete Support:
// Type modulename. followed by a CTRL + SPACE
// Yara documentation: https://yara.readthedocs.io/en/stable/writingrules.html
// Canertest
//filechanges
rule find_string
{
    meta:
        description = "Find containing string."

    strings :
        $a = "keylogger started" wide ascii nocase

    condition :
        $a
}
