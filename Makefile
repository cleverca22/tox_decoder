CFLAGS=-fPIC -I${shark} -I${glib}/include/glib-2.0 -I${glib}/lib/glib-2.0/include/

libtoxcore.so: plugin.o toxcore.o
	g++ -o $@ -shared $?

%.o: %.c
	echo foo ${shark}
	ls -l /home/clever/wireshark-1.12.7/epan/packet.h
	gcc -c $< -o $@ ${CFLAGS}

plugin.o: plugin.c
toxcore.o: toxcore.c


install:
	mkdir -pv ${out}/lib/
	cp -vi libtoxcore.so ${out}/lib