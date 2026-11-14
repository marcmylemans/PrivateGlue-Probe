# Changelog

## 2.0.0 (unreleased)

### Changed
- Works on Linux and macOS, not only Windows.
- Much faster: addresses are pinged at the same time instead of one by one.
- Reports MAC addresses (read from the operating system's neighbour table after the ping).
- Scans the real network size instead of always assuming a /24.
- Without `--subnet`, only home and office ranges are scanned. Public addresses are never
  scanned by themselves, and networks above `--max-hosts` (default 1024) are skipped.
- The server address and key can come from `PRIVATEGLUE_URL` and `PRIVATEGLUE_API_KEY`, so
  the key no longer has to be on the command line.
- `--server` takes the plain PrivateGlue address. `--backend` with the full URL still works.
- Clear messages instead of a Python error when the key is wrong, the server cannot be
  reached or something else answers.
- New: `--dry-run`, `--max-hosts`, `--workers`, `--insecure`, `--version`.
- There is no default server any more (it was `http://localhost:5000`): name it.

### Security
- Warns when the key would be sent over plain http to a public address.
- Requests have a timeout and verify the HTTPS certificate.
- `probe.exe` is no longer stored in the repository. It is built by GitHub Actions and
  published as a release with a SHA-256 checksum.
- Dependencies are pinned.

## 1.0.0 (2025-05-19)
- First version: Windows ping scan, results sent to PrivateGlue.
