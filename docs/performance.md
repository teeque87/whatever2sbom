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

The dominant cost in all three cases is `apt-cache show` (15+ subprocess calls for hash
enrichment) and Python interpreter startup overhead.

## Tuning tips

- Pass `--no-apt-cache` when you only need package identity and don't require download hashes.
  This is the single biggest win.
- Pass `--no-licenses` to skip reading and parsing every package's
  `/usr/share/doc/<pkg>/copyright` file.
- Use `--performance-metrics` to get a per-stage timing breakdown (collect / enrich / format /
  validate / write) for your own system, so you can see where time actually goes before deciding
  what to skip.
