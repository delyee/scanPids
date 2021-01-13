# Example
```shell
# check for updates: https://github.com/delyee/yara_rules/tree/master/Miners

$ cp -r ../yara_rules-master/Miners ./Rules/
$ sudo python3 scanPids.py

[!] 8831 PIDs loaded
[!] Wait starting threads...
[%] Scanned: 342 | Queue size: 8595 | Active threads: 6
[+] Rule: MiningPools, PID: 3402, Strings: [(94310235327122, '$', b'zergpool.com'), (94310235327231, '$', b'zergpool.com'), (94310235327265, '$', b'zergpool.com')]
[%] Scanned: 725 | Queue size: 8212 | Active threads: 6
[+] Rule: MiningPools, PID: 6392, Strings: [(39454734, '$', b'zergpool.com'), (140590171455454, '$', b'zergpool.com'), (47208574, '$', b'zergpool.com'), (54398350, '$', b'zergpool.com'), (58111254, '$', b'zergpool.com')]
[+] Rule: XmrigCnrigOptions, PID: 5801, Strings: [(8095638, '$', b'--donate-level'), (8094920, '$', b'--nicehash'), (8094214, '$', b'--algo'), (8094716, '$', b'--threads'), (8094183, '$', b'xmrig'), (8137312, '$', b'xmrig')]
[+] Rule: MiningPools, PID: 5801, Strings: [(8094948, '$', b'nicehash.com'), (8096990, '$', b'nicehash.com'), (8097065, '$', b'minergate.com')]
[%] Scanned: 1137 | Queue size: 7800 | Active threads: 6
...
```
