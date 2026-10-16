CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
INCLUDES := -Iinclude

LIB_OBJS := src/sha1.o src/etssign.o

.PHONY: all clean check

all: etssign

libetssign.a: $(LIB_OBJS)
	ar rcs $@ $(LIB_OBJS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

etssign: src/main.o libetssign.a
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ src/main.o libetssign.a

check: etssign
	./etssign --self-test

clean:
	rm -f src/*.o etssign libetssign.a
