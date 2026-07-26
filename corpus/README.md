# Goodware corpus (all-inclusive)

This tree ships **ready-to-use** low-entropy fill material extracted from
open-source Windows goodware.

```text
corpus/
  index.json               # chunk metadata cache (sha256, entropy, sizes)
  bundled/                 # redistributable upstream PEs (~40 MB)
    THIRD_PARTY_NOTICES.md
    manifest.toml
    *.exe
  components/              # pre-ingested chunks (used at build time)
    <id>/meta.toml
    <id>/chunks/*.bin
  sources/                 # optional operator-local EXEs (gitignored)
```

`index.json` is rewritten by `ingest` and `corpus reindex`. Build-time loads use it when
chunk sizes still match disk (fast path); otherwise components/ is rescanned.

## Out of the box

```bash
# already ingested components are committed
cargo run -p binary-filler-cli -- corpus list -c corpus

# agent build uses workspace corpus automatically (FailPolicy::ops)
cargo build -p dummy-agent --target x86_64-pc-windows-gnu --release
```

## Refresh / rebuild

```bash
./scripts/fetch-bundled-goodware.sh   # re-download upstream PEs
./scripts/rebuild-bundled-corpus.sh   # re-ingest → components/
```

## Add your own

```bash
# place under sources/ (gitignored) or bundled/ (if redistributable)
cargo run -p binary-filler-cli -- ingest \
  -s corpus/sources/mytool.exe \
  -c corpus \
  --id mytool \
  --tags gui,utility
```

## Licensing

See [`bundled/THIRD_PARTY_NOTICES.md`](bundled/THIRD_PARTY_NOTICES.md). Only
software with clear redistribution rights is bundled.
