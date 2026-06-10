# Systems and schemas

## Systems

### `dpkg`

Collects all installed packages from the local dpkg database, enriches them
with hashes from `apt-cache`, and extracts license information from
`/usr/share/doc/<pkg>/copyright`.

| Option | Description |
|---|---|
| `--distro ID` | Override the distro identifier used in package PURLs (e.g. `ubuntu`, `debian`). Auto-detected from `/etc/os-release` if omitted. |
| `--no-apt-cache` | Skip `apt-cache show` enrichment. Hashes and download metadata will be absent for most packages. |
| `--no-licenses` | Skip reading copyright files. The `licenses` field will be empty on all components. |

## Schemas

| Format | Versions | Notes |
|---|---|---|
| `cyclonedx` | `1.6` | Default. Produces a `.cdx.json` file. |
