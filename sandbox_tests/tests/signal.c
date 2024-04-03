/*
description: Signal is caught as a verdict
script: |
    expect(run(), verdict=Signaled(11))
*/

#include <stddef.h>

int main() {
    *(int *)NULL = 1;
    return 0;
}
