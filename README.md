<h1 align="center">plutonium-dbg</h1>

<h5 align=center>A kernel-based debugger for Linux applications</h4>

<p align="center">
  <a href="#key-features">Key Features</a> •
  <a href="#how-to-use">How to Use</a> •
  <a href="#setup">Setup</a> •
  <a href="#contributing">Contributing</a> •
  <a href="#license">License</a>
</p>

## Key Features

* Stealthy debugging
* No `ptrace`
* Modern kernel features
* GDB integration

## How to Use

Follow the installation instructions at <a href=#setup>Setup</a> and start your VM with the `run.sh` script.

#### Standalone

You can load the kernel module using `insmod plutonium-dbg.ko`. Once the module is loaded, you can communicate with the kernel module over IOCTL on `/dev/debugging`. When you are done with debugging, use `rmmod plutonium-dbg` to unload the module.

To enable easier communication with the kernel module in Python, the `plutonium_dbg.py` module (in `clients`) abstracts the IOCTL calls and constants used:

```python
from plutonium_dbg import debugger
dbg = debugger()

# Suspend target thread
dbg.suspend_thread(pid)

# Set breakpoint
dbg.install_breakpoint(pid, address)

# Continue thread
dbg.continue_thread(pid)
```

#### GDB

While the kernel module is loaded, you can use our GDB remote server to interact with plutonium-dbg through a GDB client. Simply start the program by launching `gdbserver.py <program>`.

To connect to a GDB server running on the VM, use the following commands from  your host GDB (this allows you to keep any of your custom settings, including plugins such as [pwndbg](https://github.com/pwndbg/pwndbg)):

    set target-architecture i386:x86_64
    target remote localhost:1337

## Setup

#### Dependencies

* QEMU (with KVM support)
* Python 3
* anything needed to compile the Linux kernel

#### Virtualization

We provide a QEMU-based VM system for running plutonium-dbg. First, check out a Linux kernel version of your choice (or clone the repository with `git clone --recursive` to automatically obtain the latest kernel sources). Then, build the kernel by running `setup/build-kernel.sh`.

Then, you can set up a Debian VM using `setup/build-vm.sh <debian release> <target folder>`.

You can start a VM by running the `run.sh` script in the VM folder. Each VM is accessible locally over SSH; we include helper scripts for SSH (`ssh.sh`) and remote copying over SCP (`scp.sh <source files...> <destination>`).

#### Compilation and Installation

Compile the kernel module by running `make` in the `module` folder, then copy the `plutonium-dbg.ko` file and any of the Python scripts you wish to use to your target machine.

#### Compilation for host system

You can also compile plutonium-dbg for your host system by replacing the path to the kernel in `module/Makefile` to `/lib/modules/$(shell uname -r)/build` (just uncomment the corresponding line). This requires the development headers for your kernel version, but allows you to avoid using QEMU. Note that plutonium-dbg is not yet stable; do not do this outside of a virtual machine unless you are happy to accidentally crash your system.

On a Debian-based distro (e.g. Ubuntu), you may install the development headers for your kernel version with:

```shell
sudo apt-get install linux-headers-$(uname -r)
```

On a Red Hat'ish distro (e.g. Fedora, RHEL, CentOS), you may do it with:

```shell
sudo yum install kernel-devel
```

Unfortunately, plutonium-dbg currently does not actually build with RHEL7'ish (e.g., CentOS 7) kernel headers - pull requests to make this actually work are welcome.

## Contributing

Contributions to plutonium-dbg are always welcome! If you encounter a bug or have a feature request, please [open an issue](https://github.com/plutonium-dbg/plutonium-dbg/issues/new). Feel free to create a [pull request](https://help.github.com/articles/creating-a-pull-request/) for your improvements.

## License

plutonium-dbg, including the GDB server, is released under the GPLv2 (or, at your choice, any later version).

----

<sup>© 2018 Tobias Holl (@TobiasHoll), Philipp Klocke (@KillPinguin)</sup>
