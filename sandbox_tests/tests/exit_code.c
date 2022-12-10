/*
description: Non-zero exit code is caught as a verdict
expect:
  exit_code: 123
*/

#include <stddef.h>

int main() { return 123; }
