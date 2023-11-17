#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
SYSROOT=$(${CROSS_COMPILE}gcc -print-sysroot)

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # clean linux
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper
    # create defconfig
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig
    # build kernel
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all
    # build all modules
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules
    # build the device tree
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs
fi

echo "Adding the Image in outdir"
cp ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi

ROOT_FS=${OUTDIR}/rootfs
mkdir -p ${ROOT_FS}/{bin,dev,etc,lib,lib64,proc,sys,sbin,tmp,usr}
mkdir -p ${ROOT_FS}/{usr/bin,usr/lib,usr/sbin}
mkdir -p ${ROOT_FS}/var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}

    # Configure busybox
    make distclean
    make defconfig
else
    cd busybox
fi

# Make and install busybox
make -j ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${ROOT_FS} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a ${ROOT_FS}/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a ${ROOT_FS}/bin/busybox | grep "Shared library"

# Add library dependencies to rootfs
cp ${SYSROOT}/lib/ld-linux-aarch64.so.1 ${ROOT_FS}/lib/.
cp ${SYSROOT}/lib64/libm.so.6 ${ROOT_FS}/lib64/.
cp ${SYSROOT}/lib64/libresolv.so.2 ${ROOT_FS}/lib64/.
cp ${SYSROOT}/lib64/libc.so.6 ${ROOT_FS}/lib64/.



echo Make device nodes
sudo mknod -m 666 ${ROOT_FS}/dev/null c 1 3
sudo mknod -m 600 ${ROOT_FS}/dev/console c 5 3
#
# Clean and build the writer utility
cd ${FINDER_APP_DIR}
make clean
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all

# Copy the finder related scripts and executables to the /home directory
# on the target rootfs
TARGET_DIR=${ROOT_FS}/home
mkdir -p ${TARGET_DIR}
cp ${FINDER_APP_DIR}/writer ${TARGET_DIR}
cp ${FINDER_APP_DIR}/finder.sh ${TARGET_DIR}
cp ${FINDER_APP_DIR}/finder-test.sh ${TARGET_DIR}
cp ${FINDER_APP_DIR}/autorun-qemu.sh ${TARGET_DIR}

# Copy the conf files
TARGET_DIR=${ROOT_FS}/home/conf
mkdir -p ${TARGET_DIR}
cp ${FINDER_APP_DIR}/conf/* ${TARGET_DIR}

echo "Chown the root directory"
sudo chown -R root:root ${ROOT_FS}/*

echo "Create initramfs.cpio.gz"
cd ${ROOT_FS}
sudo find . | sudo cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip -f ${OUTDIR}/initramfs.cpio