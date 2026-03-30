#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

if [ $# -lt 1 ]; then
    echo "Usage: $0 <pav dir>" >&2
    exit 1
fi

readonly PAV="$1"

go tool goose -out code -dir "$PAV" \
    ./advrpc ./alicebob ./auditor ./client ./cryptoffi ./cryptoffi/ffi ./cryptoutil \
    ./hashchain ./ktcore ./merkle ./netffi ./safemarshal ./server
go tool proofgen -out generatedproof -configdir code -dir "$PAV" \
    ./advrpc ./alicebob ./auditor ./client ./cryptoffi ./cryptoffi/ffi ./cryptoutil \
    ./hashchain ./ktcore ./merkle ./netffi ./safemarshal ./server
