#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <ARCH> <DESTINATION>"
    exit 1
fi

ARCH=$1
DESTINATION=$2

if [[ $ARCH -ne 32 && $ARCH -ne 64 ]]; then
    echo "Invalid value for BUILD_FOR. It should be either 32 or 64."
    exit 1
fi

if [[ $ARCH -eq 32 ]]; then
    OUTPUT_FILE="fusion.dll"
else
    OUTPUT_FILE="fusion${ARCH}.dll"
fi

rm -rf ./obj

mkdir obj

make make_objects -j$(nproc) OUTPUT_FILE="$OUTPUT_FILE" BUILD_FOR="$BUILD_FOR"
make make_output OUTPUT_FILE="$OUTPUT_FILE" BUILD_FOR="$BUILD_FOR"

rm -rf ./obj

mv -f "$OUTPUT_FILE" "$DESTINATION"
