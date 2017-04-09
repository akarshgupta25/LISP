/********************************************************************
*
* Filename: lisp_hdrs.h
*
* Description: This file includes header files that are required
*              by LISP xTRs
*
*******************************************************************/

#ifndef __LISP_HDRS_H__
#define __LISP_HDRS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include "lisp_defn.h"
#include "lisp_tdfs.h"

#endif /* __LISP_HDRS_H__ */
