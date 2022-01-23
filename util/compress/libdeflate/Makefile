#
# Use 'make help' to list available targets.
#
# Define V=1 to enable "verbose" mode, showing all executed commands.
#
# Define USE_SHARED_LIB to link the binaries to the shared library version of
# libdeflate rather than to the static library version.
#
# Define DECOMPRESSION_ONLY to omit all compression code, building a
# decompression-only library.  If doing this, you must also build a specific
# library target such as 'libdeflate.a', as the programs will no longer compile.
#
# Define DISABLE_GZIP to disable support for the gzip wrapper format.
#
# Define DISABLE_ZLIB to disable support for the zlib wrapper format.
#
# Define PREFIX to override the installation prefix, like './configure --prefix'
# in autotools-based projects (default: /usr/local)
#
# Define BINDIR to override where to install binaries, like './configure
# --bindir' in autotools-based projects (default: PREFIX/bin)
#
# Define INCDIR to override where to install headers, like './configure
# --includedir' in autotools-based projects (default: PREFIX/include)
#
# Define LIBDIR to override where to install libraries, like './configure
# --libdir' in autotools-based projects (default: PREFIX/lib)
#
# Define DESTDIR to override the installation destination directory
# (default: empty string)
#
# Define FREESTANDING to build a freestanding library, i.e. a library that
# doesn't link to any libc functions like malloc(), free(), and memcpy().
# All users will need to call libdeflate_set_memory_allocator().
#
# You can also specify a custom CC, CFLAGS, CPPFLAGS, and/or LDFLAGS.
#
##############################################################################

#### Common compiler flags.  You can add additional flags by defining CFLAGS
#### in the environment or on the 'make' command line.
####
#### The default optimization flags can be overridden, e.g. via CFLAGS="-O3" or
#### CFLAGS="-O0 -fno-omit-frame-pointer".  But this usually isn't recommended;
#### you're unlikely to get significantly better performance even with -O3.

cc-option = $(shell if $(CC) $(1) -c -x c /dev/null -o /dev/null \
	      1>&2 2>/dev/null; then echo $(1); fi)

override CFLAGS :=							\
	-O2 -fomit-frame-pointer -std=c99 -I. -Wall -Wundef		\
	$(call cc-option,-Wpedantic)					\
	$(call cc-option,-Wdeclaration-after-statement)			\
	$(call cc-option,-Wmissing-prototypes)				\
	$(call cc-option,-Wstrict-prototypes)				\
	$(call cc-option,-Wvla)						\
	$(call cc-option,-Wimplicit-fallthrough)			\
	$(CFLAGS)

FREESTANDING :=
ifdef FREESTANDING
override CPPFLAGS += -DFREESTANDING
LIB_CFLAGS += -ffreestanding -nostdlib
endif

# Don't use this option except for testing; it isn't a stable interface.
TEST_SUPPORT__DO_NOT_USE :=
ifdef TEST_SUPPORT__DO_NOT_USE
override CPPFLAGS += -DTEST_SUPPORT__DO_NOT_USE
endif

##############################################################################

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
INCDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib

SOVERSION          := 0

STATIC_LIB_SUFFIX  := .a
PROG_SUFFIX        :=
PROG_CFLAGS        :=
HARD_LINKS         := 1

# Compiling for Windows with MinGW?
ifneq ($(findstring -mingw,$(shell $(CC) -dumpmachine 2>/dev/null)),)
    STATIC_LIB_SUFFIX  := static.lib
    SHARED_LIB         := libdeflate.dll
    SHARED_LIB_SYMLINK :=
    SHARED_LIB_CFLAGS  :=
    SHARED_LIB_LDFLAGS := -Wl,--out-implib,libdeflate.lib \
                          -Wl,--output-def,libdeflate.def \
                          -Wl,--add-stdcall-alias
    PROG_SUFFIX        := .exe
    PROG_CFLAGS        := -static -municode
    HARD_LINKS         :=
    override CFLAGS    := $(CFLAGS) $(call cc-option,-Wno-pedantic-ms-format)

    # If AR was not already overridden, then derive it from $(CC).
    # Note that CC may take different forms, e.g. "cc", "gcc",
    # "x86_64-w64-mingw32-gcc", or "x86_64-w64-mingw32-gcc-6.3.1".
    # On Windows it may also have a .exe extension.
    ifeq ($(AR),ar)
        AR := $(shell echo $(CC) | \
                sed -E 's/g?cc(-?[0-9]+(\.[0-9]+)*)?(\.exe)?$$/ar\3/')
    endif

# macOS?
else ifeq ($(shell uname),Darwin)
   SHARED_LIB         := libdeflate.$(SOVERSION).dylib
   SHARED_LIB_SYMLINK := libdeflate.dylib
   SHARED_LIB_CFLAGS  := -fPIC
   SHARED_LIB_LDFLAGS := -install_name $(SHARED_LIB)

# Linux, FreeBSD, etc.
else
   SHARED_LIB         := libdeflate.so.$(SOVERSION)
   SHARED_LIB_SYMLINK := libdeflate.so
   SHARED_LIB_CFLAGS  := -fPIC
   SHARED_LIB_LDFLAGS := -Wl,-soname=$(SHARED_LIB)
endif

##############################################################################

#### Quiet make is enabled by default.  Define V=1 to disable.

ifneq ($(findstring s,$(MAKEFLAGS)),s)
ifneq ($(V),1)
        QUIET_CC       = @echo '  CC      ' $@;
        QUIET_CCLD     = @echo '  CCLD    ' $@;
        QUIET_AR       = @echo '  AR      ' $@;
        QUIET_LN       = @echo '  LN      ' $@;
        QUIET_CP       = @echo '  CP      ' $@;
        QUIET_GEN      = @echo '  GEN     ' $@;
endif
endif

##############################################################################

# Rebuild if a user-specified setting that affects the build changed.
.build-config: FORCE
	@flags=$$(							\
		echo 'USE_SHARED_LIB=$(USE_SHARED_LIB)';		\
		echo 'DECOMPRESSION_ONLY=$(DECOMPRESSION_ONLY)';	\
		echo 'DISABLE_GZIP=$(DISABLE_GZIP)';			\
		echo 'DISABLE_ZLIB=$(DISABLE_ZLIB)';			\
		echo 'FREESTANDING=$(FREESTANDING)';			\
		echo 'CC=$(CC)';					\
		echo 'CFLAGS=$(CFLAGS)';				\
		echo 'CPPFLAGS=$(CPPFLAGS)';				\
		echo 'LDFLAGS=$(LDFLAGS)';				\
	);								\
	if [ "$$flags" != "`cat $@ 2>/dev/null`" ]; then		\
		[ -e $@ ] && echo "Rebuilding due to new settings";	\
		echo "$$flags" > $@;					\
	fi

##############################################################################

COMMON_HEADERS := $(wildcard common/*.h) libdeflate.h
DEFAULT_TARGETS :=

#### Library

STATIC_LIB := libdeflate$(STATIC_LIB_SUFFIX)

LIB_CFLAGS += $(CFLAGS) -fvisibility=hidden -D_ANSI_SOURCE

LIB_HEADERS := $(wildcard lib/*.h) $(wildcard lib/*/*.h)

LIB_SRC := lib/deflate_decompress.c lib/utils.c \
	   $(wildcard lib/*/cpu_features.c)

DECOMPRESSION_ONLY :=
ifndef DECOMPRESSION_ONLY
    LIB_SRC += lib/deflate_compress.c
endif

DISABLE_ZLIB :=
ifndef DISABLE_ZLIB
    LIB_SRC += lib/adler32.c lib/zlib_decompress.c
    ifndef DECOMPRESSION_ONLY
        LIB_SRC += lib/zlib_compress.c
    endif
endif

DISABLE_GZIP :=
ifndef DISABLE_GZIP
    LIB_SRC += lib/crc32.c lib/gzip_decompress.c
    ifndef DECOMPRESSION_ONLY
        LIB_SRC += lib/gzip_compress.c
    endif
endif

STATIC_LIB_OBJ := $(LIB_SRC:.c=.o)
SHARED_LIB_OBJ := $(LIB_SRC:.c=.shlib.o)

# Compile static library object files
$(STATIC_LIB_OBJ): %.o: %.c $(LIB_HEADERS) $(COMMON_HEADERS) .build-config
	$(QUIET_CC) $(CC) -o $@ -c $(CPPFLAGS) $(LIB_CFLAGS) $<

# Compile shared library object files
$(SHARED_LIB_OBJ): %.shlib.o: %.c $(LIB_HEADERS) $(COMMON_HEADERS) .build-config
	$(QUIET_CC) $(CC) -o $@ -c $(CPPFLAGS) $(LIB_CFLAGS) \
		$(SHARED_LIB_CFLAGS) -DLIBDEFLATE_DLL $<

# Create static library
$(STATIC_LIB):$(STATIC_LIB_OBJ)
	$(QUIET_AR) $(AR) cr $@ $+

DEFAULT_TARGETS += $(STATIC_LIB)

# Create shared library
$(SHARED_LIB):$(SHARED_LIB_OBJ)
	$(QUIET_CCLD) $(CC) -o $@ $(LDFLAGS) $(LIB_CFLAGS) \
		$(SHARED_LIB_LDFLAGS) -shared $+

DEFAULT_TARGETS += $(SHARED_LIB)

ifdef SHARED_LIB_SYMLINK
# Create the symlink libdeflate.so => libdeflate.so.$SOVERSION
$(SHARED_LIB_SYMLINK):$(SHARED_LIB)
	$(QUIET_LN) ln -sf $+ $@
DEFAULT_TARGETS += $(SHARED_LIB_SYMLINK)
endif

##############################################################################

#### Programs

PROG_CFLAGS += $(CFLAGS)		 \
	       -D_POSIX_C_SOURCE=200809L \
	       -D_FILE_OFFSET_BITS=64	 \
	       -DHAVE_CONFIG_H

ALL_PROG_COMMON_HEADERS := programs/config.h \
			   programs/prog_util.h \
			   programs/test_util.h
PROG_COMMON_SRC      := programs/prog_util.c \
			programs/tgetopt.c
NONTEST_PROG_SRC     := programs/gzip.c
TEST_PROG_COMMON_SRC := programs/test_util.c
TEST_PROG_SRC        := programs/benchmark.c \
			programs/checksum.c \
			$(filter-out $(TEST_PROG_COMMON_SRC),$(wildcard programs/test_*.c))

NONTEST_PROGRAMS := $(NONTEST_PROG_SRC:programs/%.c=%$(PROG_SUFFIX))
DEFAULT_TARGETS  += $(NONTEST_PROGRAMS)
TEST_PROGRAMS    := $(TEST_PROG_SRC:programs/%.c=%$(PROG_SUFFIX))

PROG_COMMON_OBJ      := $(PROG_COMMON_SRC:%.c=%.o)
NONTEST_PROG_OBJ     := $(NONTEST_PROG_SRC:%.c=%.o)
TEST_PROG_COMMON_OBJ := $(TEST_PROG_COMMON_SRC:%.c=%.o)
TEST_PROG_OBJ        := $(TEST_PROG_SRC:%.c=%.o)

ALL_PROG_OBJ	     := $(PROG_COMMON_OBJ) $(NONTEST_PROG_OBJ) \
			$(TEST_PROG_COMMON_OBJ) $(TEST_PROG_OBJ)

# Generate autodetected configuration header
programs/config.h:scripts/detect.sh .build-config
	$(QUIET_GEN) CC="$(CC)" CFLAGS="$(PROG_CFLAGS)" $< > $@

# Compile program object files
$(ALL_PROG_OBJ): %.o: %.c $(ALL_PROG_COMMON_HEADERS) $(COMMON_HEADERS) \
			.build-config
	$(QUIET_CC) $(CC) -o $@ -c $(CPPFLAGS) $(PROG_CFLAGS) $<

# Link the programs.
#
# Note: the test programs are not compiled by default.  One reason is that the
# test programs must be linked with zlib for doing comparisons.

ifdef USE_SHARED_LIB
LIB := $(SHARED_LIB)
else
LIB := $(STATIC_LIB)
endif

$(NONTEST_PROGRAMS): %$(PROG_SUFFIX): programs/%.o $(PROG_COMMON_OBJ) $(LIB)
	$(QUIET_CCLD) $(CC) -o $@ $(LDFLAGS) $(PROG_CFLAGS) $+

$(TEST_PROGRAMS): %$(PROG_SUFFIX): programs/%.o $(PROG_COMMON_OBJ) \
			$(TEST_PROG_COMMON_OBJ) $(LIB)
	$(QUIET_CCLD) $(CC) -o $@ $(LDFLAGS) $(PROG_CFLAGS) $+ -lz

ifdef HARD_LINKS
# Hard link gunzip to gzip
gunzip$(PROG_SUFFIX):gzip$(PROG_SUFFIX)
	$(QUIET_LN) ln -f $< $@
else
# No hard links; copy gzip to gunzip
gunzip$(PROG_SUFFIX):gzip$(PROG_SUFFIX)
	$(QUIET_CP) cp -f $< $@
endif

DEFAULT_TARGETS += gunzip$(PROG_SUFFIX)

##############################################################################

all:$(DEFAULT_TARGETS)

# Install the files.  Note: not all versions of the 'install' program have the
# '-D' and '-t' options, so don't use them; use portable commands only.
install:all
	install -d $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR) $(DESTDIR)$(BINDIR)
	install -m644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)
	install -m755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)
	install -m644 libdeflate.h $(DESTDIR)$(INCDIR)
	install -m755 gzip$(PROG_SUFFIX) \
		$(DESTDIR)$(BINDIR)/libdeflate-gzip$(PROG_SUFFIX)
	ln -f $(DESTDIR)$(BINDIR)/libdeflate-gzip$(PROG_SUFFIX)		\
	      $(DESTDIR)$(BINDIR)/libdeflate-gunzip$(PROG_SUFFIX)
	if [ -n "$(SHARED_LIB_SYMLINK)" ]; then				\
		ln -sf $(SHARED_LIB)					\
		       $(DESTDIR)$(LIBDIR)/$(SHARED_LIB_SYMLINK);	\
	fi

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(STATIC_LIB)				\
	      $(DESTDIR)$(LIBDIR)/$(SHARED_LIB)				\
	      $(DESTDIR)$(INCDIR)/libdeflate.h				\
	      $(DESTDIR)$(BINDIR)/libdeflate-gzip$(PROG_SUFFIX)		\
	      $(DESTDIR)$(BINDIR)/libdeflate-gunzip$(PROG_SUFFIX)
	if [ -n "$(SHARED_LIB_SYMLINK)" ]; then				\
		rm -f $(DESTDIR)$(LIBDIR)/$(SHARED_LIB_SYMLINK);	\
	fi

test_programs:$(TEST_PROGRAMS)

# A minimal 'make check' target.  This only runs some quick tests;
# use scripts/run_tests.sh if you want to run the full tests.
check:test_programs
	LD_LIBRARY_PATH=. ./benchmark$(PROG_SUFFIX) < ./benchmark$(PROG_SUFFIX)
	for prog in test_*; do		\
		LD_LIBRARY_PATH=. ./$$prog || exit 1;	\
	done

# Run the clang static analyzer.
scan-build:
	scan-build --status-bugs make all test_programs

# Run shellcheck on all shell scripts.
shellcheck:
	shellcheck scripts/*.sh

help:
	@echo "Available targets:"
	@echo "------------------"
	@for target in $(DEFAULT_TARGETS) $(TEST_PROGRAMS); do \
		echo -e "$$target";		\
	done

clean:
	rm -f *.a *.dll *.exe *.exp *.dylib *.so \
		lib/*.o lib/*/*.o \
		lib/*.obj lib/*/*.obj \
		lib/*.dllobj lib/*/*.dllobj \
		programs/*.o programs/*.obj \
		$(DEFAULT_TARGETS) $(TEST_PROGRAMS) programs/config.h \
		libdeflate.lib libdeflate.def libdeflatestatic.lib \
		.build-config

realclean: clean
	rm -f tags cscope*

FORCE:

.PHONY: all install uninstall test_programs check scan-build shellcheck help \
	clean realclean

.DEFAULT_GOAL = all
