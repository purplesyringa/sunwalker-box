/*
description: An unknown syscall suspends
script: |
    expect(prefork(), verdict=Suspended)
*/

#include <unistd.h>

int main() { syscall(12345); }
