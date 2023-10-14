BPF_TARGETS := tc_prog_kern
BPF_C = ${BPF_TARGETS:=.c}
BPF_OBJ = ${BPF_C:.c=.o}

COMMON_DIR ?= ../common/
include $(COMMON_DIR)/common.mk

$(BPF_OBJ): %.o: %.c  Makefile $(EXTRA_DEPS) $(OBJECT_LIBBPF)
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

all: $(BPF_OBJ)
clean:
	rm -f *.o *.ll