/* recv.c - collector for the payload's serial sink.
 *
 * Frame from payload.S:
 *
 *    C0 DE | Event(8) | Graft(8) | stream... | CR LF
 *
 * Each stream word is 8 bytes, most significant first, which is the exact
 * byte order of the loaded qword.  Words are written out little-endian so the
 * result is a raw memory image you can point any disassembler or carving tool
 * at.
 *
 *   pxerecv -d /dev/ttyUSB0 -o dump.bin -m dump.map
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>

static int read_all(int fd, uint8_t *buf, size_t n, int timeout_ms)
{
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(fd, buf + got, n - got);
    if (r > 0) { got += (size_t)r; continue; }
    if (r == 0 || errno == EAGAIN) {
      if (timeout_ms <= 0) break;
      usleep(1000);
      timeout_ms--;
      continue;
    }
    break;
  }
  return (int)got;
}

int main(int argc, char **argv)
{
  const char *dev = NULL, *out = "dump.bin", *map = "dump.map";
  int baud = B115200, c;
  static const struct option lo[] = {
    {"dev", 1, 0, 'd'}, {"out", 1, 0, 'o'}, {"map", 1, 0, 'm'},
    {"baud", 1, 0, 'b'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}
  };
  while ((c = getopt_long(argc, argv, "d:o:m:b:h", lo, NULL)) != -1) {
    switch (c) {
    case 'd': dev = optarg; break;
    case 'o': out = optarg; break;
    case 'm': map = optarg; break;
    case 'b': baud = atoi(optarg); break;
    case 'h': fprintf(stderr, "pxerecv -d <tty> [-o dump.bin] [-m dump.map]\n");
              return 0;
    default: return 2;
    }
  }
  if (!dev) { fprintf(stderr, "need -d <tty>\n"); return 2; }

  int fd = open(dev, O_RDONLY | O_NOCTTY | O_NONBLOCK);
  struct termios tio;
  if (fd < 0) { perror(dev); return 1; }
  tcgetattr(fd, &tio);
  cfmakeraw(&tio);
  tio.c_cflag |= CLOCAL | CREAD;
  cfsetispeed(&tio, baud);
  cfsetospeed(&tio, baud);
  tcsetattr(fd, TCSANOW, &tio);

  FILE *fo = fopen(out, "wb");
  FILE *fm = fopen(map, "w");
  if (!fo || !fm) { perror(out); return 1; }

  uint8_t win[1024];
  size_t  wlen = 0;
  int     locked = 0, done = 0;
  uint64_t event = 0, graft = 0, offset = 0;
  uint8_t  word[8];
  size_t   wfill = 0;

  fprintf(fm, "# event     0x%016llx\n", 0ULL);
  fprintf(fm, "# graft     0x%016llx\n", 0ULL);
  fprintf(fm, "# offset    byte offset in %s\n\n", out);

  while (!done) {
    uint8_t b;
    if (read_all(fd, &b, 1, 200) != 1)
      continue;

    /* Rolling 2-byte sync. */
    win[wlen++ & 1023] = b; wlen &= 1023;
    if (!locked) {
      if (wlen >= 2 && win[(wlen - 2) & 1023] == 0xc0 &&
          win[(wlen - 1) & 1023] == 0xde) {
        if (read_all(fd, (uint8_t *)&event, 8, 500) == 8 &&
            read_all(fd, (uint8_t *)&graft, 8, 500) == 8) {
          /* frame is BE */
          uint64_t e = 0, g = 0;
          for (int k = 0; k < 8; k++) {
            e = (e << 8) | (((uint8_t *)&event)[k]);
            g = (g << 8) | (((uint8_t *)&graft)[k]);
          }
          event = e; graft = g;
          locked = 1; wfill = 0;
          fprintf(fm, "# event     0x%016llx\n", (unsigned long long)event);
          fprintf(fm, "# graft     0x%016llx\n", (unsigned long long)graft);
          printf("[+] frame: event=%016llx graft=%016llx\n",
                 (unsigned long long)event, (unsigned long long)graft);
        }
      }
      continue;
    }

    if (wlen >= 2 && win[(wlen - 2) & 1023] == '\r' &&
        win[(wlen - 1) & 1023] == '\n' && wfill == 0) {
      done = 1;
      break;
    }

    word[wfill++] = b;
    if (wfill == 8) {
      /* BE word -> LE file, and record where it lives. */
      fputc(word[7], fo); fputc(word[6], fo); fputc(word[5], fo);
      fputc(word[4], fo); fputc(word[3], fo); fputc(word[2], fo);
      fputc(word[1], fo); fputc(word[0], fo);
      wfill = 0;
      offset += 8;
    }
  }

  if (wfill)
    fwrite(word, 1, wfill, fo);

  fclose(fo); fclose(fm); close(fd);
  printf("[+] %llu bytes -> %s\n", (unsigned long long)offset, out);
  return 0;
}
