/*
description: There is no controlling terminal
script: |
  expect(run())
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main() {
  int fd = open("/dev/tty", O_RDWR);
  if (fd != -1) {
    close(fd);
    fprintf(stderr, "Opening /dev/tty did not fail due to ENXIO\n");
    return 1;
  }
  if (errno != ENXIO) {
    perror("open");
    return 1;
  }
  return 0;
}
