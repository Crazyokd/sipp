CFLAGS=-g -ggdb -fno-omit-frame-pointer -Wall -Wextra -Wpedantic -std=gnu99 -fvisibility=hidden -Wno-implicit-fallthrough
LDFLAGS=-Wl,--as-needed -L. -Wl,-R. -Wl,-Bstatic -lsipp -Wl,-Bdynamic

C_SOURCES := $(wildcard *.c)
D_FILES := $(patsubst %.c,%.d,$(C_SOURCES))
O_FILES := $(patsubst %.c,%.o,$(C_SOURCES))

.PHONY: clean all generate-deps help
all: generate-deps libsipp.a libsipp.so sipp-example

generate-deps: $(D_FILES)

sipp-example: example.o libsipp.so libsipp.a
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

libsipp.so: $(C_SOURCES)
	$(CC) -fPIC -shared $^ -o $@ $(CFLAGS)

libsipp.a: $(O_FILES)
	$(AR) rcs $@ $^

%.d: %.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

include $(wildcard *.d)

format:
	find . -type f -name "*.[ch]" | xargs clang-format -i

help:
	@$(MAKE) --print-data-base --question |       						  \
	awk '/^[^.%][-a-zA-Z0-9_]*:/ {print substr($$1, 1, length($$1)-1)}' | \
	sort |  									                          \
	grep -v "Makefile" |												  \
	pr --omit-pagination --width=80 --columns=4

clean:
	rm -f *.o *.d libsipp.a libsipp.so sipp-example
