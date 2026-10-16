CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
INCLUDES := -Iinclude

LIB_OBJS := src/sha1.o src/ets5sign.o

.PHONY: all clean check

all: ets5sign

libets5sign.a: $(LIB_OBJS)
	ar rcs $@ $(LIB_OBJS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

ets5sign: src/main.o libets5sign.a
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ src/main.o libets5sign.a

check: ets5sign
	./ets5sign --self-test

clean:
	rm -f src/*.o ets5sign libets5sign.a
