rule Suspicious_Triage_Artifacts {
    strings:
        $a = "telegram.org" nocase
        $b = "attachedTemplate" nocase
        $c = "JavaScript" nocase
        $d = "amsiInitFailed" nocase
    condition:
        any of them
}
