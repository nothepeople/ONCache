LLC := llc
CLANG := clang
CC := gcc
CPP := g++

COMMON_DIR ?= ../common/
LIBBPF_DIR ?= ../libbpf/src/
YAML_DIR ?= ../yaml-cpp/build/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a
OBJECT_YAML = $(YAML_DIR)/libyaml-cpp.a

EXTRA_DEPS  += $(COMMON_DIR)/common_defines.h

CFLAGS ?= -g -I../headers/ -I../common/ -I../yaml-cpp/include/
LDFLAGS ?= -L$(LIBBPF_DIR) -L$(YAML_DIR)

LIBS = -l:libbpf.a -l:libyaml-cpp.a -lz -lelf 

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk
