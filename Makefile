# Douane kernel module Makefile
#
# This file is responsible to compile and load the kernel module in 2 ways:
#  - Without DKMS (Just compile and insert the kernel module with insmod and rmmod)
#  - With DKMS (Add, build and install, using DKMS, the kernel module using "dkms add", "dkms build" and "dkms install")
#
# Douane kernel module Makefile
# Copyright (C) 2013  Guillaume Hain <zedtux@zedroot.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Name of the module
MODULE_NAME=douane
# Module filename after compilation
MODULE_NAME_KO=$(MODULE_NAME).ko
# Ensure $M variable is set
ifeq ($(M),)
	# When calling make, the $M variable is the path in the kernel
	# source code (/usr/src/linux-*)
	# For other action we use the current path
	M=.
endif
# Get the version from the VERSION file
MODULE_VERSION=$(shell cat $M/VERSION)
# Objects to compile when calling make
obj-m += douane.o
# Where the module source will be placed before to call dkms add, build and install
DKMS_ROOT_PATH=/usr/src/$(MODULE_NAME)-$(MODULE_VERSION)
# Check if the module is loaded or not
MODPROBE_OUTPUT=$(shell lsmod | grep douane)
# Compilation flags
EXTRA_CFLAGS=-g -DDOUANE_VERSION=\"$(MODULE_VERSION)\"
# Compilation flags with debug
#EXTRA_CFLAGS=-g -DDOUANE_VERSION=\"$(MODULE_VERSION)\" -DDEBUG

ifeq ($(KERNEL_VERSION),)
KERNEL_VERSION=$(shell uname -r)
endif

# make
all:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(shell pwd) modules

# make clean
clean:
	$(MAKE) -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean

# make install (While developing, without using DKMS)
install:
	@echo "Installing Douane Linux kernel module..."
	@insmod $(MODULE_NAME_KO)

# make uninstall (While developing, without using DKMS)
uninstall:
	@echo "Uninstalling Douane Linux kernel module..."
	@rmmod $(MODULE_NAME_KO)

# make reinstall
reinstall:
	$(MAKE) uninstall
	$(MAKE) install

# ~~~~ DKMS actions ~~~~
# make dkms (Install the module using DKMS)
dkms:
	@echo "Installing Douane Linux kernel module version $(MODULE_VERSION)..."
	@sed -i -e '/^PACKAGE_VERSION=/ s/=.*/=\"$(MODULE_VERSION)\"/' dkms.conf
	@mkdir $(DKMS_ROOT_PATH)
	@cp `pwd`/dkms.conf $(DKMS_ROOT_PATH)
	@cp `pwd`/douane.c $(DKMS_ROOT_PATH)
	@cp `pwd`/Makefile $(DKMS_ROOT_PATH)
	@cp `pwd`/network_activity_message.h $(DKMS_ROOT_PATH)
	@cp `pwd`/VERSION $(DKMS_ROOT_PATH)
	@dkms add -m $(MODULE_NAME) -v $(MODULE_VERSION)
	@dkms build -m $(MODULE_NAME) -v $(MODULE_VERSION)
	@dkms install --force -m $(MODULE_NAME) -v $(MODULE_VERSION)
	@echo "Loading Douane Linux kernel module..."
	@modprobe $(MODULE_NAME)

# make cleandkms (Remove the module from DKMS)
cleandkms:
	@if [ ! -z "$(MODPROBE_OUTPUT)" ]; then \
		echo "Uninstalling Douane Linux kernel module...";\
		rmmod $(MODULE_NAME);\
	fi
	@echo "Removing Douane Linux kernel module..."
	@dkms remove -m $(MODULE_NAME) -v $(MODULE_VERSION) --all
	@rm -rf $(DKMS_ROOT_PATH)

# make rebuilddkms
rebuilddkms:
	$(MAKE) cleandkms; \
	$(MAKE) dkms
# ~~~~~~~~~~~~~~~~~~~~~~
