include arch/lkl/auto.conf

KBUILD_CFLAGS += -fno-builtin

exec_format = $(firstword $(subst -, ,$(OUTPUT_FORMAT)))

ifneq (,$(filter elf64 elf32,$(exec_format)))
KBUILD_CFLAGS += -fPIC
else ifneq (,$(filter pe,$(exec_format)))
ifneq ($(OUTPUT_FORMAT),pe-x86-64)
prefix=_
endif
# workaround for #include_next<stdarg.h> errors
LINUXINCLUDE := -isystem arch/lkl/include/system $(LINUXINCLUDE)
# workaround for https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52991
KBUILD_CFLAGS += -mno-ms-bitfields
else
$(error Unrecognized platform: $(OUTPUT_FORMAT))
endif

ifeq ($(shell uname -s), Linux)
NPROC=$(shell nproc)
else # e.g., FreeBSD
NPROC=$(shell sysctl -n hw.ncpu)
endif

LDFLAGS_vmlinux += -r
LKL_ENTRY_POINTS := lkl_start_kernel lkl_sys_halt lkl_syscall lkl_trigger_irq \
	lkl_get_free_irq lkl_put_irq lkl_is_running lkl_bug lkl_printf

ifeq ($(OUTPUT_FORMAT),elf32-i386)
LKL_ENTRY_POINTS += \
	__x86.get_pc_thunk.bx __x86.get_pc_thunk.dx __x86.get_pc_thunk.ax \
	__x86.get_pc_thunk.cx __x86.get_pc_thunk.si __x86.get_pc_thunk.di
endif

core-y += arch/lkl/kernel/
core-y += arch/lkl/mm/
core-y += arch/lkl/drivers/

all: lkl.o

# objcopy trick is taken from rumpkernel
GCCSYMBOLS=__umoddi3|__udivdi3|__aeabi_idiv|__aeabi_idivmod|__aeabi_llsl|__multi3
GCCSYMBOLS:=$(GCCSYMBOLS)|__aeabi_llsr|__aeabi_uidiv|__aeabi_uidivmod|__aeabi_uldivmod
GCCATOMIC=__sync_synchronize|__sync_fetch_and_sub_4|__sync_fetch_and_add_4
GCCATOMIC:=$(GCCATOMIC)|__sync_fetch_and_and_4|__sync_fetch_and_or_4
VMLINUX_SYMS=__start___ex_table|__stop___ex_table|boot_cmdline
EXP_SYMRENAME=rump|RUMP|bmk_|lib_|nuse_|lkl_|__tls|__initcall_start
EXP_SYMRENAME:=$(EXP_SYMRENAME)|__bzero|__sched
EXP_SYMRENAME:=$(EXP_SYMRENAME)|__initcall_end|__gcov|_end|_GLOBAL_OFFSET_TABLE|__assert13
EXP_SYMRENAME:=$(EXP_SYMRENAME)|${GCCSYMBOLS}|${GCCATOMIC}'${_SYMQUIRK}'
EXP_SYMRENAME:=$(EXP_SYMRENAME)${RUMP_SYM_NORENAME:D|${RUMP_SYM_NORENAME}}|${VMLINUX_SYMS}

define make_ns_symbols
	${Q}echo "  OBJCPY	" $1 $2;	\
	${NM} -go $1 | awk ' 	\
	$$NF!~/^'$(prefix)'(${EXP_SYMRENAME})/ \
	{s=$$NF;sub(/^'$(prefix)'/, "&rumpns_", s); print $$NF, s}'\
	| sort | uniq  > $2.renametab; \
	$(OBJCOPY) $(OBJCOPY_REMOVE_SECTION) -L __start___ex_table \
	-L __stop___ex_table --preserve-dates \
	--redefine-syms $2.renametab $1 $2; \
	rm -f $2.renametab
endef

lkl.o: vmlinux
	$(call make_ns_symbols,vmlinux,lkl.o)

arch/lkl/include/generated/uapi/asm/syscall_defs.h: vmlinux
	$(OBJCOPY) -j .syscall_defs -O binary --set-section-flags .syscall_defs=alloc $< $@
	$(Q) export tmpfile=$(shell mktemp); \
	sed 's/\x0//g' $@ > $$tmpfile; mv $$tmpfile $@ ; rm -f $$tmpfile

install: lkl.o headers arch/lkl/include/generated/uapi/asm/syscall_defs.h
	@echo "  INSTALL	$(INSTALL_PATH)/lib/lkl.o"
	@mkdir -p $(INSTALL_PATH)/lib/
	@cp lkl.o $(INSTALL_PATH)/lib/
	@$(srctree)/arch/lkl/scripts/headers_install.py \
		$(subst -j,-j$(NPROC),$(findstring -j,$(MAKEFLAGS))) \
		$(INSTALL_PATH)/include

archclean:
	$(Q)$(MAKE) $(clean)=$(boot)

define archhelp
  echo '  install	- Install library and headers to INSTALL_PATH/{lib,include}'
endef



