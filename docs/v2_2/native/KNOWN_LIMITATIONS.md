# Known limitations

1. **Approval authority is not isolated** from the server's Windows account (same DPAPI scope). Reported as
   `approval_authority_isolated=false`. A separate Windows account or hardware-backed key would be required to make it a
   privilege boundary.
2. **Unkeyed audit hash chain** — detects accidental/partial tampering only.
3. **No elevation.** Operations that need Administrator (most service changes, MSI/EXE machine installs, some Apache
   services) return `needs_elevation`/`ACCESS_DENIED`; the owner must run them elevated manually. UAC is never bypassed.
4. **Managed-process isolation** is Job Object limits only (no AppContainer/integrity-level drop, no network isolation).
5. **Output encoding**: child output is decoded as UTF-8 with replacement; legacy OEM code-page tools may show mojibake.
6. **1C coverage** is descriptor/Apache/OData oriented. No cluster administration (rac/ras), no infobase data access, no
   configuration load/dump; OData returns metadata names and counts only, never business records.
7. **Apache discovery** relies on the Windows service command line and configured roots; unusual layouts (multiple
   services sharing one conf, `Include` through symlinked dirs) are reported as findings, not guessed.
8. **Installer verification** uses Authenticode (`Get-AuthenticodeSignature`) and configured publishers/thumbprints;
   when none are configured every installer is "unverified" and always needs approval.
9. **Upload limits**: 25 MiB per file, extension allowlist, 16 concurrent uploads, 24 h TTL.
10. **Not verified in this session**: real 1C platform, real Apache+wsap module, real installers, tunnel round trip via
    ChatGPT. These are recorded BLOCKED (not PASS) in FINAL_VERIFICATION.md. Production gates G01–G13 are not claimed.
11. **Tests were written but not run during development** (operator policy); the first execution is the final
    verification run.

## Administrator token and "no deletion" (operator decision 2026-10-10)
The operator chose to run the whole v2 server (supervisor, backend, tunnel) with the administrator token
(`update_v2_native_autostart.ps1 -Elevated`, one UAC consent by the operator; `-Unelevate` reverts).
Windows cannot give "admin without delete" at OS level, so "no deletion" is a TOOL-LEVEL policy
(`dc_v2/winops/deletion_policy.py`, config `deny_deletion`, default true): PowerShell/cmd/exec/process_start text is
scanned for deletion verbs, destructive utilities, git history destruction and dynamic-code constructs that could hide a
verb; automated MSI rollback (an uninstall) is refused. It runs before any approval is requested and is audited.
It is a best-effort text policy, NOT an OS guarantee: an operator-approved interpreter (python/node/...) or installer
runs arbitrary code and can delete; those stay behind a per-run approval showing the exact parameters. v1 file tools
still have no delete tool. With an administrator token a compromised server process has far greater impact than
before; prefer `-Unelevate` when elevated work is not needed.
