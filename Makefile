PARTS = user_prog tc_prog
PARTS_CLEAN = $(addsuffix _clean,$(PARTS))

COMMON_DIR ?= ./common/
LIBBPF_DIR ?= ./libbpf/src/
YAML_DIR ?= ./yaml-cpp/
include $(COMMON_DIR)/common.mk

$(OBJECT_LIBBPF):
	cd $(LIBBPF_DIR) && $(MAKE) all OBJDIR=.; \
	mkdir -p build; $(MAKE) install_headers DESTDIR=build OBJDIR=.; \

$(OBJECT_YAML):
	cd $(YAML_DIR) && mkdir -p build && cd build; \
	cmake .. && $(MAKE); \

$(PARTS):
	$(MAKE) -C $@ all

$(PARTS_CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean

.PHONY: all clean $(PARTS) $(PARTS_CLEAN)
all: $(OBJECT_LIBBPF) $(OBJECT_YAML) $(PARTS)
core: $(PARTS)
clean: $(PARTS_CLEAN)
