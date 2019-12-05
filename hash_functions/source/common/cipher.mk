#
# University of Luxembourg
# Laboratory of Algorithmics, Cryptology and Security (LACS)
#
# FELICS - Fair Evaluation of Lightweight Cryptographic Systems
#
# Copyright (C) 2017 University of Luxembourg
#
# Written in 2017 by Virat Shejwalkar <virat.shejwalkar@uni.lu>
#
# This file is part of FELICS.
#
# FELICS is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# FELICS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.
#

#
# Call this makefile from a cipher source directory or build directory to build 
#	... the given cipher:
#	make -f ./../../../common/cipher.mk [ARCHITECTURE=[AVR|MSP|ARM|PC]]
#		[DEBUG=[0|1|3|7]] [MEASURE_CYCLE_COUNT=[0|1]] [SCENARIO=[0|1A|1B|1C|2]] 
#		[COMPILER_OPTIONS='...'] [all|clean|cleanall|help]
#
# 	Examples: 
#		make -f ./../../../common/cipher.mk
#		make -f ./../../../common/cipher.mk ARCHITECTURE=PC DEBUG=1
#			SCENARIO=0
#		make -f ./../../../common/cipher.mk clean
#


PCMAKEFILE = ./../../../../../common/architecture/pc.mk
AVRMAKEFILE = ./../../../../../common/architecture/avr.mk
MSPMAKEFILE = ./../../../../../common/architecture/msp.mk
ARMMAKEFILE = ./../../../../../common/architecture/arm.mk


SOURCEDIR = ./../source
BUILDDIR = ./../build

COMMONSOURCEDIR = ./../../../common
ROTATIONSDIR = ./../../../../../common/source/rotations
SCENARIO1SOURCEDIR = $(COMMONSOURCEDIR)/scenario1
SCENARIO2SOURCEDIR = $(COMMONSOURCEDIR)/scenario2


INCLUDES = -I$(SOURCEDIR) -I$(COMMONSOURCEDIR) -I$(ROTATIONSDIR)

VPATH = $(SOURCEDIR):$(COMMONSOURCEDIR)


SOURCES = $(wildcard $(SOURCEDIR)/*.c)
OBJS = $(subst $(SOURCEDIR)/, , $(SOURCES:.c=.o))

SCENARIO1SOURCES = $(wildcard $(SCENARIO1SOURCEDIR)/*.c)
SCENARIO1ALLOBJS = $(subst $(SCENARIO1SOURCEDIR)/, , $(SCENARIO1SOURCES:.c=.o))
SCENARIO1OBJS = $(filter-out scenario1.o, $(SCENARIO1ALLOBJS))

SCENARIO2SOURCES = $(wildcard $(SCENARIO2SOURCEDIR)/*.c)
SCENARIO2ALLOBJS = $(subst $(SCENARIO2SOURCEDIR)/, , $(SCENARIO2SOURCES:.c=.o))
SCENARIO2OBJS = $(filter-out scenario2.o, $(SCENARIO2ALLOBJS))

LSTS = $(OBJS:.o=.lst)
CIPHERLSTS = main.lst common.lst
SCENARIO1LSTS=$(SCENARIO1OBJS:.o=.lst)
SCENARIO2LSTS=$(SCENARIO2OBJS:.o=.lst)


ifeq ($(SCENARIO), 1A)
TARGET=target1a
LSTS += $(SCENARIO1LSTS)
else
ifeq ($(SCENARIO), 1B)
TARGET=target1b
LSTS += $(SCENARIO1LSTS)
else
ifeq ($(SCENARIO), 1C)
TARGET=target1c
LSTS += $(SCENARIO1LSTS)
else
ifeq ($(SCENARIO), 2)
TARGET=target2
LSTS += $(SCENARIO2LSTS)
else
TARGET=target
LSTS += $(CIPHERLSTS)
endif
endif
endif
endif


CURRENTPATHDIRS = $(subst /, , $(CURDIR))
LASTCURRENTPATHDIR = $(word $(words $(CURRENTPATHDIRS)), $(CURRENTPATHDIRS))
CIPHERNAME = $(lastword $(subst $(LASTCURRENTPATHDIR), , $(CURRENTPATHDIRS)))  


DELIMITER = ----------


.PHONY : all clean cleanall help


all : post-build

.PHONY : post-build
post-build : main-build
	@echo $(DELIMITER) End building $(CIPHERNAME) $(DELIMITER)

.PHONY : main-build
main-build : \
		pre-build \
		$(TARGET)

.PHONY : pre-build
pre-build : \
		pre-build-include \
		pre-build-debug \
		pre-build-scenario \
		pre-build-measure_cycle_count \
		pre-build-compiler_options \
		pre-build-scenario-name-transfer
	@echo $(DELIMITER) Start building $(CIPHERNAME) $(DELIMITER)


.PHONY : pre-build-include
pre-build-include :
ifeq ($(ARCHITECTURE), AVR)
	@echo Building for $(ARCHITECTURE) ...
include $(AVRMAKEFILE)
$(eval CFLAGS += -D $(ARCHITECTURE))
else
ifeq ($(ARCHITECTURE), MSP)
	@echo Building for $(ARCHITECTURE) ...
include $(MSPMAKEFILE)
$(eval CFLAGS += -D $(ARCHITECTURE))
else
ifeq ($(ARCHITECTURE), ARM)
	@echo Building for $(ARCHITECTURE) ...
include $(ARMMAKEFILE)
$(eval CFLAGS += -D $(ARCHITECTURE))
else
	@echo Building for PC ...
include $(PCMAKEFILE)
$(eval CFLAGS += -D PC)
endif
endif
endif

.PHONY : pre-build-debug
pre-build-debug :
ifdef DEBUG
	@echo Building with DEBUG flag set to $(DEBUG) ...
$(eval CFLAGS += -D DEBUG=$(DEBUG))
else
	@echo Building with DEBUG flag NOT set ...
endif

.PHONY : pre-build-scenario
pre-build-scenario :
ifdef SCENARIO
	@echo Building with SCENARIO flag set to $(SCENARIO) ...
else
	@echo Building with SCENARIO flag NOT set ...
endif

.PHONY : pre-build-measure_cycle_count
pre-build-measure_cycle_count :
ifdef MEASURE_CYCLE_COUNT
	@echo Building with MEASURE_CYCLE_COUNT flag set to $(MEASURE_CYCLE_COUNT) \
		...
$(eval CFLAGS += -D MEASURE_CYCLE_COUNT=$(MEASURE_CYCLE_COUNT))
else
	@echo Building with MEASURE_CYCLE_COUNT flag NOT set ...
endif

.PHONY : pre-build-compiler_options
pre-build-compiler_options :
ifdef COMPILER_OPTIONS
	@echo Building with COMPILER_OPTIONS flag set to $(COMPILER_OPTIONS) ...
$(eval CFLAGS += $(COMPILER_OPTIONS))
else
	@echo Building with COMPILER_OPTIONS flag NOT set ...
endif

.PHONY : pre-build-scenario-name-transfer
pre-build-scenario-name-transfer :
ifeq ($(SCENARIO), 1A)
$(eval CFLAGS += -D SCENARIO=11)
else
ifeq ($(SCENARIO), 1B)
$(eval CFLAGS += -D SCENARIO=12)
else
ifeq ($(SCENARIO), 1C)
$(eval CFLAGS += -D SCENARIO=13)
else
ifeq ($(SCENARIO), 2)
$(eval CFLAGS += -D SCENARIO=2)
endif
endif
endif
endif

.PHONY : target
target : \
		cipher.elf \
		cipher.lst \
		$(LSTS)

.PHONY : target1a
target1a : \
		scenario1a.elf \
		scenario1a.lst \
		$(LSTS)

.PHONY : target1b
target1b : \
		scenario1b.elf \
		scenario1b.lst \
		$(LSTS)

.PHONY : target1c
target1c : \
		scenario1c.elf \
		scenario1c.lst \
		$(LSTS)

.PHONY : target2 
target2 : \
		scenario2.elf \
		scenario2.lst \
		$(LSTS)


cipher.elf : \
		$(OBJS) \
		main.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, main.o) $(addprefix $(BUILDDIR)/, common.o) \
		$(LDLIBS) -o $(BUILDDIR)/$@

scenario1a.elf : \
		$(OBJS) \
		scenario1.o \
		update_scenario1.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, scenario1.o) \
		$(addprefix $(BUILDDIR)/, update_scenario1.o) \
		$(addprefix $(BUILDDIR)/, common.o) $(LDLIBS) -o $(BUILDDIR)/$@

scenario1b.elf : \
		$(OBJS) \
		scenario1.o \
		update_scenario1.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, scenario1.o) \
		$(addprefix $(BUILDDIR)/, update_scenario1.o) \
		$(addprefix $(BUILDDIR)/, common.o) $(LDLIBS) -o $(BUILDDIR)/$@

scenario1c.elf : \
		$(OBJS) \
		scenario1.o \
		update_scenario1.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, scenario1.o) \
		$(addprefix $(BUILDDIR)/, update_scenario1.o) \
		$(addprefix $(BUILDDIR)/, common.o) $(LDLIBS) -o $(BUILDDIR)/$@

scenario2.elf : \
		$(OBJS) \
		scenario2.o \
		update_scenario2_hmac.o \
		update_scenario2_pmac.o \
		mac_key.o \
		common.o
	$(CC) $(LDFLAGS) $(addprefix $(BUILDDIR)/, $(OBJS)) \
		$(addprefix $(BUILDDIR)/, scenario2.o) \
		$(addprefix $(BUILDDIR)/, update_scenario2_hmac.o) \
		$(addprefix $(BUILDDIR)/, update_scenario2_pmac.o) \
		$(addprefix $(BUILDDIR)/, mac_key.o) \
		$(addprefix $(BUILDDIR)/, common.o) $(LDLIBS) -o $(BUILDDIR)/$@


cipher.bin : $(BUILDDIR)/cipher.elf
	$(OBJCOPY) -O binary $< $@

scenario1a.bin : $(BUILDDIR)/scenario1a.elf
	$(OBJCOPY) -O binary $< $@

scenario1b.bin : $(BUILDDIR)/scenario1b.elf
	$(OBJCOPY) -O binary $< $@

scenario1c.bin : $(BUILDDIR)/scenario1c.elf
	$(OBJCOPY) -O binary $< $@

scenario2.bin : $(BUILDDIR)/scenario2.elf
	$(OBJCOPY) -O binary $< $@


%.o : \
		%.c \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h \
		$(SOURCEDIR)/data_types.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@


main.o : \
		$(COMMONSOURCEDIR)/main.c \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

common.o : \
		$(COMMONSOURCEDIR)/common.c \
		$(COMMONSOURCEDIR)/common.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/test_vectors.h \
		$(SOURCEDIR)/constants.h 
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@


scenario1.o : \
		$(SCENARIO1SOURCEDIR)/scenario1.c \
		$(SCENARIO1SOURCEDIR)/scenario1.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

update_scenario1.o : \
		$(SCENARIO1SOURCEDIR)/update_scenario1.c \
		$(SCENARIO1SOURCEDIR)/scenario1.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

scenario2.o : \
		$(SCENARIO2SOURCEDIR)/scenario2.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

update_scenario2_pmac.o : \
		$(SCENARIO2SOURCEDIR)/update_scenario2_pmac.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

update_scenario2_hmac.o : \
		$(SCENARIO2SOURCEDIR)/update_scenario2_hmac.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@

mac_key.o : \
		$(SCENARIO2SOURCEDIR)/mac_key.c \
		$(SCENARIO2SOURCEDIR)/scenario2.h \
		$(COMMONSOURCEDIR)/cipher.h \
		$(COMMONSOURCEDIR)/common.h \
		$(SOURCEDIR)/constants.h
	$(CC) -c $(CFLAGS) $< $(INCLUDES) -o $(BUILDDIR)/$@


cipher.lst : cipher.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

scenario1a.lst : scenario1a.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

scenario1b.lst : scenario1b.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

scenario1c.lst : scenario1c.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

scenario2.lst : scenario2.elf
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@

%.lst : %.o
	$(OBJDUMP) $(OBJDUMPFLAGS) $(BUILDDIR)/$< > $(BUILDDIR)/$@


clean :
	@echo $(DELIMITER) Begin cleaning: $(CIPHERNAME) $(DELIMITER)
	rm -f *~
	rm -f $(SOURCEDIR)/*~
	rm -f $(COMMONSOURCEDIR)/*~

	rm -f $(BUILDDIR)/cipher.elf
	rm -f $(BUILDDIR)/cipher.bin
	rm -f $(BUILDDIR)/cipher.lst

	rm -f $(BUILDDIR)/scenario1.elf
	rm -f $(BUILDDIR)/scenario1.bin
	rm -f $(BUILDDIR)/scenario1.lst

	rm -f $(BUILDDIR)/scenario2.elf
	rm -f $(BUILDDIR)/scenario2.bin
	rm -f $(BUILDDIR)/scenario2.lst
	
	rm -f $(BUILDDIR)/main.o 
	rm -f $(BUILDDIR)/common.o
	
	rm -f $(addprefix $(BUILDDIR)/, $(OBJS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO1ALLOBJS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO2ALLOBJS))
	
	rm -f $(addprefix $(BUILDDIR)/, $(LSTS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO1LSTS))
	rm -f $(addprefix $(BUILDDIR)/, $(SCENARIO2LSTS))

	rm -f $(BUILDDIR)/*.su
	rm -f $(BUILDDIR)/*.map
	@echo $(DELIMITER) End cleaning: $(CIPHERNAME) $(DELIMITER)


cleanall :
	@echo $(DELIMITER) Begin cleaning: $(CIPHERNAME) $(DELIMITER)
	rm -f *~
	rm -f $(SOURCEDIR)/*~
	rm -f $(COMMONSOURCEDIR)/*~
	rm -f $(SCENARIO1SOURCEDIR)/*~
	rm -f $(SCENARIO2SOURCEDIR)/*~
	rm -f $(BUILDDIR)/*
	@echo $(DELIMITER) End cleaning: $(CIPHERNAME) $(DELIMITER)


help:
	@echo ""
	@echo -n "Call this makefile from a cipher source directory or build "
	@echo 		"directory to build the given cipher:"
	@echo -n "	make -f ./../../../common/cipher.mk "
	@echo -n		"[ARCHITECTURE=[AVR|MSP|ARM|PC]] [DEBUG=[0|1|3|7]] "
	@echo -n		"[MEASURE_CYCLE_COUNT=[0|1]] [SCENARIO=[0|1A|1B|1C|2]] " 
	@echo -n		"[COMPILER_OPTIONS='...'] [all|clean|cleanall|help]"
	@echo ""
	@echo ""
	@echo " 	Examples: "
	@echo "		make -f ./../../../common/cipher.mk"
	@echo -n "		make -f ./../../../common/cipher.mk ARCHITECTURE=PC "
	@echo 			"DEBUG=1 SCENARIO=0"
	@echo "		make -f ./../../../common/cipher.mk clean"
	@echo ""
