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
