/* recv.c - collector for the payload's serial sink.
 *
 * Wire format produced by payload.S, every 64-bit field most-significant
 * byte first:
 *
 *   C0 DE <event> <graft>            open frame
 *   C1 <start> <end> <data...>       one block per requested range
 *   C0 DE <event> <graft>            close frame, only after the last byte
 *
 * The file is written back little-endian, so it is a raw memory image in the
 * order the ranges were walked.  The map records address, size and file
 * offset for each block.
 *
 *   ./pxerecv -d /dev/ttyUSB0 -o dump.bin -m dump.map
 *
 * A missing close frame means the dump was truncated: that is the difference
 * between "the payload finished" and "the platform died halfway", and it is
 * worth keeping in the notes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <termios.h>

#define SYNC0 0xc0
#define SYNC1 0xde
#define MARK  0xc1

static int g_fd;

struct block {
  uint64_t start, end, file_off;
};

static int rd(uint8_t *p, size_t n, int ticks)
{
  size_t got = 0;
  while (got < n) {
    ssize_t r = read(g_fd, p + got, n - got);
    if (r > 0) { got += (size_t)r; continue; }
    if (r == 0 || errno == EAGAIN) {
      if (ticks-- <= 0) return -1;
      usleep(1000);
      continue;
    }
    return -1;
  }
  return 0;
}

static uint64_t get_be64(const uint8_t *p)
{
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
  return v;
}

static void put_le64(FILE *f, uint64_t v)
{
  for (int i = 0; i < 8; i++) fputc((int)((v >> (8 * i)) & 0xff), f);
}

int main(int argc, char **argv)
{
  const char *dev = NULL, *out = "dump.bin", *map = "dump.map";
  speed_t baud = B115200;
  int c;
  static const struct option lo[] = {
    {"dev", 1, 0, 'd'}, {"out", 1, 0, 'o'}, {"map", 1, 0, 'm'},
    {"baud", 1, 0, 'b'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}
  };

  while ((c = getopt_long(argc, argv, "d:o:m:b:h", lo, NULL)) != -1) {
    switch (c) {
    case 'd': dev = optarg; break;
    case 'o': out = optarg; break;
    case 'm': map = optarg; break;
    case 'b': baud = (speed_t)atoi(optarg); break;
    case 'h':
      fprintf(stderr, "pxerecv -d <tty> [-o dump.bin] [-m dump.map] [-b 115200]\n");
      return 0;
    default: return 2;
    }
  }
  if (!dev) { fprintf(stderr, "need -d <tty>\n"); return 2; }

  g_fd = open(dev, O_RDONLY | O_NOCTTY | O_NONBLOCK);
  if (g_fd < 0) { perror(dev); return 1; }

  struct termios tio;
  if (tcgetattr(g_fd, &tio) == 0) {
    cfmakeraw(&tio);
    tio.c_cflag |= CLOCAL | CREAD;
    tio.c_cflag &= ~CRTSCTS;
    tio.c_cc[VMIN] = 0;
    tio.c_cc[VTIME] = 1;
    cfsetispeed(&tio, baud);
    cfsetospeed(&tio, baud);
    tcsetattr(g_fd, TCSANOW, &tio);
    tcflush(g_fd, TCIFLUSH);
  }

  FILE *fo = fopen(out, "wb");
  if (!fo) { perror(out); return 1; }

  uint8_t b, prev = 0;
  int have_prev = 0, in_frame = 0, done = 0;
  uint64_t ev = 0, graft = 0, offset = 0, cur_start = 0, cur_bytes = 0;
  uint8_t word[8];
  size_t wfill = 0;
  struct block blocks[256];
  size_t nblocks = 0;

  while (!done && rd(&b, 1, 400) == 0) {
    if (!in_frame) {
      if (have_prev && prev == SYNC0 && b == SYNC1) {
        uint8_t hdr[16];
        if (rd(hdr, sizeof(hdr), 800) != 0) break;
        uint64_t e = get_be64(hdr), g = get_be64(hdr + 8);
        if (!ev) {
          ev = e; graft = g; in_frame = 1;
          printf("[+] open: event=%016llx graft=%016llx\n",
                 (unsigned long long)ev, (unsigned long long)graft);
        } else {
          printf("[+] close frame, dump complete\n");
          done = 1;
        }
        prev = 0; have_prev = 0;
        continue;
      }
      prev = b; have_prev = 1;
      continue;
    }

    if (b == MARK) {
      uint8_t ab[16];
      if (rd(ab, sizeof(ab), 800) != 0) break;
      if (nblocks < sizeof(blocks) / sizeof(blocks[0])) {
        blocks[nblocks].start    = get_be64(ab);
        blocks[nblocks].end      = get_be64(ab + 8);
        blocks[nblocks].file_off = offset;
        nblocks++;
      }
      cur_start = get_be64(ab);
      cur_bytes = 0;
      printf("[*] block %016llx .. %016llx\n",
             (unsigned long long)get_be64(ab),
             (unsigned long long)get_be64(ab + 8));
      continue;
    }

    word[wfill++] = b;
    if (wfill == 8) {
      uint64_t v = get_be64(word);
      put_le64(fo, v);
      offset += 8;
      cur_bytes += 8;
      wfill = 0;
      (void)cur_start;
    }
  }

  fclose(fo);
  close(g_fd);

  FILE *fm = fopen(map, "w");
  if (!fm) { perror(map); return 1; }
  fprintf(fm, "# pxerecv map\n# image: %s\n# event: 0x%016llx\n"
              "# graft: 0x%016llx\n#\n# address             size      offset\n",
          out, (unsigned long long)ev, (unsigned long long)graft);
  for (size_t i = 0; i < nblocks; i++) {
    uint64_t size = blocks[i].end > blocks[i].start
                      ? blocks[i].end - blocks[i].start : 0;
    fprintf(fm, "0x%016llx  %8llu  %8llu\n",
            (unsigned long long)blocks[i].start,
            (unsigned long long)size,
            (unsigned long long)blocks[i].file_off);
  }
  if (!done)
    fprintf(fm, "# WARNING: no close frame, dump truncated\n");
  fclose(fm);

  printf("[+] %llu bytes -> %s (%zu block%s)%s\n",
         (unsigned long long)offset, out, nblocks, nblocks == 1 ? "" : "s",
         done ? "" : " - TRUNCATED");
  return done ? 0 : 1;
}
