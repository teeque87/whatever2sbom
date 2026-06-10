# Performance

End-to-end wall-clock on **Ubuntu 26.04**, 5-run average via [hyperfine](https://github.com/sharkdp/hyperfine) (1 warmup excluded):

```bash
sudo apt install hyperfine
make bench-e2e
```

| Configuration | Wall-clock | σ |
|---|---:|---:|
| `--no-licenses --no-apt-cache` — dpkg collect + format + validate only | **3.804 s** | ± 0.158 s |
| `--no-licenses` — + apt-cache hash enrichment | **9.092 s** | ± 1.279 s |
| full pipeline — + DEP-5 copyright extraction | **8.362 s** | ± 0.269 s |

The dominant cost in all three cases is `apt-cache show` (15+ subprocess calls for hash enrichment) and Python interpreter startup overhead. Pass `--no-apt-cache` when you only need package identity and don't require download hashes.

> See the [Go port](https://github.com/teeque87/whatever2sbom/tree/go-port) for a single static binary that runs the same pipeline **3–23× faster** with no Python runtime required.
