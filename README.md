to decrypt packets, apply toxcore.patch to toxcore and rebuild

then start a tox client like this
```
TOX_LOG_KEYS=/tmp/keys LD_PRELOAD=./result/lib/liblogkeys.so qtox
```
followed by wireshark like this
```
TOX_LOG_KEYS=/tmp/keys wireshark
```
