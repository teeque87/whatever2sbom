from pathlib import Path


def get_os_info() -> dict[str, str]:
    """Parse /etc/os-release into a flat dict of lowercase keys."""
    info: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                info[k.lower()] = v.strip().strip('"')
    except (FileNotFoundError, PermissionError):
        pass
    return info