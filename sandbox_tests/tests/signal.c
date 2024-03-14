/*
description: Signal is caught as a verdict
script: |
  expect(run(), limit_verdict="Signaled", exit_code=-11)
*/

#include <stddef.h>

int main() {
    *(int *)NULL = 1;
    return 0;
}
