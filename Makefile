CFLAGS=-fPIC -I${shark} -I${glibdev}/include/glib-2.0 -I${glib}/lib/glib-2.0/include/ -Werror=implicit-function-declaration

libtoxcore.so: plugin.o toxcore.o
	g++ -o $@ -shared -lsodium $?

%.o: %.c
	@echo wireshark sources in ${shark}
	gcc -c $< -o $@ ${CFLAGS}

plugin.o: plugin.c
toxcore.o: toxcore.c


install:
	mkdir -pv ${out}/lib/
	cp -vi libtoxcore.so ${out}/lib