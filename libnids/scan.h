/*
  Copyright (c) 1999 Rafal Wojtczuk <nergal@7bulls.com>. All rights reserved.
  See the file COPYING for license details.
*/

#ifndef _NIDS_SCAN_H
#define _NIDS_SCAN_H
#include <netinet/ip.h>
#include <stdint.h>

struct scan {
    uint32_t addr;
    unsigned short port;
    uint8_t flags;
};

struct host {
    struct host *next;
    struct host *prev;
    uint32_t addr;
    int modtime;
    int n_packets;
    struct scan *packets;
};

void scan_init(void);
void scan_exit(void);
void detect_scan(struct ip *);

#endif /* _NIDS_SCAN_H */
