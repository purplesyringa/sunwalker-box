/*
description: A simple program works as intended
script: |
  expect(run(input="world"), stdout="Hello, world!", stderr="Bye, world!")
  run_reset()
*/

#include <stdio.h>

int main() {
  char name[32];
  fgets(name, sizeof(name), stdin);
  printf("Hello, %s!", name);
  fprintf(stderr, "Bye, %s!", name);
  return 0;
}
