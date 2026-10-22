This is the poc for 20 oct's exploit

```
php2shell_poc.py [OPTIONS]

  -t HOST   Target host (default: 127.0.0.1)
  -p PORT   Target port (default: 19268)
  -s SEC    Stall duration in seconds; must be > min_freq (default: 1.5)
  -r N      Number of trigger rounds (default: 1)
  -m        Monitor mode — read session mid-stall to confirm arming
  --spray N Heap spray: N dummy 256-byte file parts to exhaust the ZendMM
            bin before arData is freed, raising the probability that the
            stale write hits a live zend_string (type confusion → crash)
  -v        Verbose
  --verify  Verify lab configuration before triggering
```
