# Phase B — engine hash proposal (Founder vetting)

**Date:** 2026-09-22 (Asia/Colombo)  
**Status:** **PROPOSAL ONLY** — `ENGINE_ALLOWLIST` stays empty. Do **not** treat this as pinned.  
**Action requested:** Founder verifies artifact bytes, decides zip-vs-binary install path, then human-edits allowlist.

## Why this is a proposal

`sentinel_core` engine download currently fetches a single URL, verifies sha256 of that exact file, and installs it as `$SENTINEL_HOME/bin/<filename>`.

ProjectDiscovery ships **ZIP** archives. Official `*_checksums.txt` hashes are for the **zip**, not the inner binary. Until download learns unzip+inner-hash (or we pin a raw binary), allowlist entries must not be silently applied.

**This note did not download binaries** — only public checksum text files from GitHub Releases.

## Candidates (linux/amd64 primary)

### subfinder — v2.16.0

| Field | Value |
| --- | --- |
| Upstream | https://github.com/projectdiscovery/subfinder/releases/tag/v2.16.0 |
| Artifact (zip) | https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_amd64.zip |
| Published sha256 (zip) | `1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60` |
| Checksums file | https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_checksums.txt |
| License | MIT (upstream) |

Full published checksums.txt:

```
64b57772588d446b3cf1d3acf73eaeb73299c23e5d9c8d28b5516bee4889e6d0  subfinder_2.16.0_linux_386.zip
1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60  subfinder_2.16.0_linux_amd64.zip
b6d0e7fb118988e49910614fddf9f23f952e797b45ede700bf730ff2eada9da7  subfinder_2.16.0_linux_arm.zip
c81d49559c0f630177be9e347e502e7a3d474aacc6ff78291ffcb4964367d63d  subfinder_2.16.0_linux_arm64.zip
8300c4d98f75596b7e8460ba6f3322dfeda4674bc2bcbde14d61d098db260b50  subfinder_2.16.0_macOS_amd64.zip
af55827c9e6cdc530cca377ad459214ead16daf1b79d90e3dcefa387f644e057  subfinder_2.16.0_macOS_arm64.zip
8c71dec8cd03b53a4128a962f2c51495ab26cbd7eda8c07f4bfceacaeb1e0472  subfinder_2.16.0_windows_386.zip
ef760f0a064c22811100c75a61da35ba73d71398cb99ae85d32d0eed44496ab8  subfinder_2.16.0_windows_amd64.zip
442ab5a802953035767cddafc05a988df9625249e5695af9ee3a4d731c7ff60b  subfinder_2.16.0_windows_arm64.zip
```

### httpx — v1.11.0

| Field | Value |
| --- | --- |
| Upstream | https://github.com/projectdiscovery/httpx/releases/tag/v1.11.0 |
| Artifact (zip) | https://github.com/projectdiscovery/httpx/releases/download/v1.11.0/httpx_1.11.0_linux_amd64.zip |
| Published sha256 (zip) | `5dce96e7315cff24be7aab3b032f23f7a71b7711a17f8189ebe601f2588f2f87` |
| Checksums file | https://github.com/projectdiscovery/httpx/releases/download/v1.11.0/httpx_1.11.0_checksums.txt |
| License | MIT (upstream) |

Full published checksums.txt:

```
1ddae8e59c7a32d547de7684c1c3aa44092ecbbdb84fc359ed3736a8c7dbd3a8  httpx_1.11.0_linux_386.zip
5dce96e7315cff24be7aab3b032f23f7a71b7711a17f8189ebe601f2588f2f87  httpx_1.11.0_linux_amd64.zip
506c301bda5034979b5f170f9f016d79c100e0cc71034965a636fd0f19a1a334  httpx_1.11.0_linux_arm.zip
2b5d9ec3d3750df41e04e4216b1400d2ad862d1cb9ebe68ae501b2299cb5b3a5  httpx_1.11.0_linux_arm64.zip
6434bbbb0f39ce5ec357736b4f8286e810cbca3dcc23d666666044cbf03b4c1d  httpx_1.11.0_macOS_amd64.zip
ec63baf67dfadf78c9410d55f847469dffa2a6f08f6da3124f7fca146f598956  httpx_1.11.0_macOS_arm64.zip
ca481a7471cf77640ea33fd1c6e611d0dfe75d400f106bb9b35904cce93c50a4  httpx_1.11.0_windows_386.zip
d65a4445de3fcea8b096caf5157f4641d50bfe5ffb749596538b0659c4273a7e  httpx_1.11.0_windows_amd64.zip
```

## Draft allowlist shape (DO NOT commit until vetted)

```python
ENGINE_ALLOWLIST = {
    "subfinder": {
        "version": "2.16.0",
        "url": "https://github.com/projectdiscovery/subfinder/releases/download/v2.16.0/subfinder_2.16.0_linux_amd64.zip",
        "sha256": "1b7f9c608e9a5bd59e609a5e09710d63c5485e92d3d49dc2c16eb4fdbe10cb60",  # ZIP hash — needs unzip support OR replace with binary hash
        "filename": "subfinder",
    },
    "httpx": {
        "version": "1.11.0",
        "url": "https://github.com/projectdiscovery/httpx/releases/download/v1.11.0/httpx_1.11.0_linux_amd64.zip",
        "sha256": "5dce96e7315cff24be7aab3b032f23f7a71b7711a17f8189ebe601f2588f2f87",  # ZIP hash
        "filename": "httpx",
    },
}
```

## Founder checklist

1. Re-fetch `*_checksums.txt` and confirm sha256 lines match this note
2. Decide: extend downloader for zip+extract **or** pin a raw binary URL + hash of the binary bytes
3. Confirm license + supply-chain comfort for ProjectDiscovery releases
4. Only then edit `packages/sentinel_core/src/sentinel_core/engine_allowlist.py`
5. Wire Eye `--tools` after allowlist non-empty

## Deferred (not proposed here)

naabu, nuclei, dnsx, katana, ffuf — same process later; still catalogued as deferred.
