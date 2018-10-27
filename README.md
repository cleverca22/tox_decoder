to decrypt packets, start a tox client like this
```
TOX_LOG_KEYS=/tmp/keys LD_PRELOAD=./result/lib/liblogkeys.so qtox
```
followed by wireshark like this
```
TOX_LOG_KEYS=/tmp/keys wireshark
```
the wireshark plugin should be in a path like:
```
-r-xr-xr-x 1 root root 29K Dec 31  1969 /home/clever/.local/lib/wireshark/plugins/2.6/epan/libtoxcore.so
```

example output

![decrypted ping](http://i.imgur.com/vN26HOV.png)
