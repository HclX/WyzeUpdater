#!/bin/sh
set -e
patch_rootfs() {
    local IN_FILE=$1
    local OUT_FILE=$2
    local PATCH_DIR=$3

    if [ ! -f "$IN_FILE" ];then
        echo "Input file [$IN_FILE] doesn't exist"
        return 1
    fi

    if [ ! -d "$PATCH_DIR" ];then
        echo "Patch directory [$PATCH_DIR] doesn't exist"
        return 1
    fi

    if [ -f "$OUT_FILE" ] && [ -z "$CLEAN" ];then
        echo "Output file [$OUT_FILE] already exists, skipping..."
        return 0
    fi

    echo "Processing input image $IN_FILE..."

    local TMP_DIR=$(mktemp -d -t wh-XXXXXXXXXX)
    echo "Using temporary directory $TMP_DIR..."

    unsquashfs -d $TMP_DIR/rootfs $IN_FILE >/dev/null

    chmod a+w $TMP_DIR/rootfs/etc/shadow
    cp -r $PATCH_DIR/* $TMP_DIR/rootfs/
    chmod a-w $TMP_DIR/rootfs/etc/shadow

    touch $TMP_DIR/rootfs/etc/init.d/.wyzehacks
    mksquashfs $TMP_DIR/rootfs/ $OUT_FILE -noappend -all-root -comp xz >/dev/null

    ORIG_SIZE=$(wc -c < $IN_FILE)
    NEW_SIZE=$(wc -c < $OUT_FILE)
    dd if=/dev/zero bs=1 count=$(($ORIG_SIZE - $NEW_SIZE)) >> $OUT_FILE

    if [ -z $DEBUG ]; then
        rm -rf $TMP_DIR
    fi
}

TMP_DIR=$(mktemp -d -t wh-XXXXXXXXXX)
../hms_telnet/encrypt -d 4.32.4.295.tar -o $TMP_DIR/ota.tar
tar xvf $TMP_DIR/ota.tar -C $TMP_DIR

patch_rootfs $TMP_DIR/Upgrade/rootfs $TMP_DIR/rootfs2 ./patch
rm -rf $TMP_DIR/Upgrade/*

cp Upgrade/* $TMP_DIR/Upgrade/
echo "FWGRADEUP=" > $TMP_DIR/Upgrade/PARA.null
echo "FWGRADEUP=rootfs" > $TMP_DIR/Upgrade/PARA.rootfs
cp $TMP_DIR/rootfs2 $TMP_DIR/Upgrade/rootfs

tar --sort=name \
    --owner=root:0 \
    --group=root:0 \
    --mtime='1970-01-01' \
    --dereference \
    -C $TMP_DIR \
    -cf $TMP_DIR/hms_hack.tar Upgrade

../hms_telnet/encrypt -e $TMP_DIR/hms_hack.tar -o ../hms_hack.bin
if [ -z $DEBUG ]; then
    rm -rf $TMP_DIR
fi
