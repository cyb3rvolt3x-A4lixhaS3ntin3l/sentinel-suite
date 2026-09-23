# sentinel-suite (meta)

Brand install name for the full monorepo products:

| Console script | From |
| --- | --- |
| `sentinel` | this meta → `sentinel-cli` |
| `shadowseye` | `packages/shadowseye` |
| `gungnir` | `packages/gungnir` |

## Install (path / git — PyPI not published yet)

```bash
git clone https://github.com/cyb3rvolt3x-A4lixhaS3ntin3l/sentinel-suite.git
cd sentinel-suite
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e packages/sentinel_core \
            -e packages/shadowseye \
            -e packages/gungnir \
            -e packages/sentinel_cli \
            -e packages/sentinel_suite
sentinel doctor
```

Future (when published — **not** claimed today):

```text
pipx install shadowseye
pipx install gungnir
pipx install sentinel-suite
```

See [`docs/INSTALL.md`](../../docs/INSTALL.md).
