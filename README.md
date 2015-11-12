to decrypt packets, apply toxcore.patch to toxcore and rebuild

then start a tox client like this
```
TOX_LOG_KEYS=/tmp/keys qtox
```
followed by wireshark like this
```
TOX_LOG_KEYS=/tmp/keys wireshark
```
