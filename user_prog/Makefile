USER_TARGETS += tc_prog_loader
USER_TARGETS_CPP := set_map
USER_C := ${USER_TARGETS:=.c}
USER_OBJ := ${USER_C:.c=.o}

COMMON_DIR ?= ../common/
include $(COMMON_DIR)/common.mk

common_user.o: common_user.c common_user.h
	$(CC) $(CFLAGS) -c -o $@ $<

$(USER_TARGETS): %: %.c  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) common_user.o $(EXTRA_DEPS)
	$(CC) -Wall $(CFLAGS) $(LDFLAGS) -o $@ common_user.o \
	 $< $(LIBS)

$(USER_TARGETS_CPP): %: %.cpp  $(OBJECT_LIBBPF) Makefile $(COMMON_MK) common_user.o $(EXTRA_DEPS)
	$(CPP) -Wall $(CFLAGS) $(LDFLAGS) -o $@ common_user.o \
	 $< $(LIBS)

all: common_user.o $(USER_TARGETS) $(USER_TARGETS_CPP)
clean:
	rm -f common_user.o $(USER_TARGETS) $(USER_TARGETS_CPP)
