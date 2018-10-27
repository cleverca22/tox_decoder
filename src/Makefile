CFLAGS=-fPIC `pkg-config --cflags glib-2.0` -Werror=implicit-function-declaration

all: libtoxcore.so liblogkeys.so

libtoxcore.so: plugin.o toxcore.o
	g++ -o $@ -shared -lsodium $^

liblogkeys.so: logkeys.o
	gcc -ldl -shared -fPIC -o $@ $^

%.o: %.c
	@echo wireshark sources in ${shark}
	gcc -c $< -o $@ ${CFLAGS}

plugin.o: plugin.c
toxcore.o: toxcore.c


install: libtoxcore.so liblogkeys.so
	mkdir -pv ${out}/lib/
	cp -vi libtoxcore.so ${out}/lib
	cp -vi liblogkeys.so ${out}/lib
