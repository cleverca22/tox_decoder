to decrypt packets, start a tox client like this
```
TOX_LOG_KEYS=/tmp/keys LD_PRELOAD=./result/lib/liblogkeys.so qtox
```
followed by wireshark like this
```
TOX_LOG_KEYS=/tmp/keys wireshark
```
example output

![decrypted ping](http://i.imgur.com/vN26HOV.png)
