#!/bin/bash

function check()
{
    for f in $1
    do
        uncrustify -c uncrustify.cfg --check $f
        if [ $? -ne 0 ]; then
          echo "$f: Format check failed"
          exit 1
        fi
    done
}

check "src/*.c"
check "src/include/*.h"
check "src/include/walfile/*.h"
check "test/testcases/*.h"
check "src/libpgmoneta/*.c"
check "src/libpgmoneta/walfile/*.c"
check "test/testcases/*.c"
