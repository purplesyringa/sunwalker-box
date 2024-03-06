/*
description: Non-zero exit code is caught as a verdict
script: |
  expect(run(), exit_code=123)
*/

#include <stddef.h>

int main() { return 123; }
