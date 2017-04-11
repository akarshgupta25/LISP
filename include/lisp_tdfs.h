/********************************************************************
*
* Filename: lisp_tdfs.h
*
* Description: This file contains the structures and enums used in
*              LISP
*
*******************************************************************/

#ifndef __LISP_TDFS_H__
#define __LISP_TDFS_H__

struct list_head 
{
    struct list_head *next, *prev;
};

typedef struct
{
    uint32_t  eid;
    uint32_t  mask;
#if 0
    uint8_t   prefLen;
#endif
} tEidPrefix;

typedef struct __tEidPrefixRlocMap
{
    struct list_head list;
    tEidPrefix       eidPrefix;
    uint32_t         rloc;
    uint32_t         recTtl;
    uint8_t          isProxySet;
} tEidPrefixRlocMap;

typedef struct
{
    char               *pEidIfList[LISP_MAX_EID_IF_NUM];
    uint8_t            numEidIf;
    uint32_t           mapSRIpAddr;
    tEidPrefixRlocMap  eidRlocMap[LISP_MAX_EID_IF_NUM];
    int                rawSockFd[LISP_MAX_EID_IF_NUM]; /* Rx/Tx end system 
                                                        * traffic */
    int                rxLispPktSock; /* Rx LISP encapsulated traffic 
                                       * at 4341 */
    int                txLispPktSock; /* Tx LISP encapsulated traffic */
    int                rxLispCntrlSock; /* Rx control packets at 4342 */
    int                txLispCntrlSock; /* Tx/Rx control packets to MS/MR */
    pthread_t          itrTaskId;
    pthread_t          etrTaskId;
    struct list_head   itrEidRlocMapCacheHead;
    pthread_mutex_t    itrMapCacheLock;
} tLispGlobals;

typedef struct
{
    int                lispCntrlSock; /* Rx/Tx control packets to xTR */
    struct list_head   eidRlocMapDbHead;
} tLispMSMRGlobals;

typedef struct
{
    uint8_t    ihl:4;
    uint8_t    version:4;
    uint8_t    tos;
    uint16_t   totLen;
    uint16_t   id;
    uint16_t   fragOffset;
    uint8_t    ttl;
    uint8_t    protocol;
    uint16_t   checksum;
    uint32_t   srcIpAddr;
    uint32_t   dstIpAddr;
    /*The options start here. */
} tIpv4Hdr;

typedef struct
{
    uint8_t    flags:3;
    uint8_t    instBit:1;
    uint8_t    mapVerBit:1;
    uint8_t    echoNoReqBit:1;
    uint8_t    locStatBit:1;
    uint8_t    nonceBit:1;
    uint8_t    nonceHigh;
    uint16_t   nonceLow;
    uint32_t   instIdLocStat;
} tLispHdr;

typedef struct __tMapReqFlags
{
    uint8_t    smrBit:1;
    uint8_t    probeBit:1;
    uint8_t    mapDataBit:1;
    uint8_t    authBit:1;
    uint8_t    smrInvokBit:1;
    uint8_t    pitrBit:1;
    uint8_t    pad:2;
} tMapReqFlags;

typedef struct
{
    uint8_t    rsvd;
    uint8_t    dstEidPrefLen;
    uint16_t   dstEidPrefAfi;
    uint32_t   dstEid;
} tMapReqRec;

typedef struct
{
    uint8_t    smrBit:1;
    uint8_t    probeBit:1;
    uint8_t    mapDataBit:1;
    uint8_t    authBit:1;
    uint8_t    type:4;
    uint8_t    rsvd1:6;
    uint8_t    smrInvokBit:1;
    uint8_t    pitrBit:1;
    uint8_t    itrRlocCount:5;
    uint8_t    rsvd2:3;
    uint8_t    recordCount;
    uint32_t   nonceHigh;
    uint32_t   nonceLow;
    uint16_t   srcEidAfi;
    uint16_t   srcEidHi;
    uint16_t   srcEidLo;
    uint16_t   itrRlocAfi;
    uint16_t   itrRlocHi;
    uint16_t   itrRlocLo;
    /* Map Request Rec starts here */
} tMapReqHdr;

typedef struct
{
    uint8_t    priority;
    uint8_t    weight;
    uint8_t    mPriority;
    uint8_t    mWeight;
    uint16_t   Rbit:1;
    uint16_t   pBit:1;
    uint16_t   Lbit:1;
    uint16_t   unusedFlags:13;
    uint16_t   rlocAfi;
    uint32_t   rloc;
} tRlocLoc;

typedef struct
{
    uint32_t   recTtl;
    uint8_t    locCount;
    uint8_t    eidPrefLen;
    uint16_t   rsvd1:12;
    uint16_t   authBit:1;
    uint16_t   act:3;
    uint16_t   mapVerNum:12;
    uint16_t   rsvd2:4;
    uint16_t   eidPrefixAfi;
    uint32_t   eidPrefix;
    /* loc starts here */
} tRlocRecord;

typedef struct
{
    uint8_t    rsvd1:3;
    uint8_t    proxyBit:1;
    uint8_t    type:4;
    uint8_t    rsvd2;
    uint8_t    mapNotBit:1;
    uint8_t    rsvd3:7;
    uint8_t    recordCount;
    uint32_t   nonceHigh;
    uint32_t   nonceLow;
    uint16_t   keyId;
    uint16_t   authDataLen;
    uint32_t   authData;
    /* Record starts here */
} tMapRegHdr;

typedef struct
{
    uint8_t    rsvd1:1;
    uint8_t    secBit:1;
    uint8_t    echoNonceBit:1;
    uint8_t    probeBit:1;
    uint8_t    type:4;
    uint8_t    rsvd2;
    uint8_t    rsvd3;
    uint8_t    recordCount;
    uint32_t   nonceHigh;
    uint32_t   nonceLow;
    /* Record starts here */
} tMapRepHdr;

typedef struct
{
    struct list_head list;
    uint32_t         eid;
} tEndSysMovedEid;

enum
{
    LISP_MAP_REQ_MSG = 1,
    LISP_MAP_REP_MSG,
    LISP_MAP_REG_MSG,
    LISP_MAP_NOTIFY_MSG,
    LISP_ENCP_CNTRL_MSG = 8
};

enum
{
    LISP_IPV4_AFI = 1,
    LISP_IPV6_AFI
};

/* Kernel linked list implementation functions */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

static inline void 
INIT_LIST_HEAD (struct list_head *list)
{
    if (list == NULL)
    {
        printf ("[%s]: Invalid paramater!!\r\n", __func__);
        return;  
    }

    list->next = list->prev = list;
    return;
}

static inline void 
list_add (struct list_head *entry, struct list_head *prev,
          struct list_head *next)
{
    if ((entry == NULL) || (prev == NULL) || (next == NULL))
    {   
        printf ("[%s]: Invalid paramater!!\r\n", __func__);
        return;
    }   

    next->prev = entry;
    entry->next = next;
    entry->prev = prev;
    prev->next = entry;
    return;
}

static inline void 
list_add_head (struct list_head *entry, struct list_head *head)
{
    if ((entry == NULL) || (head == NULL))
    {
        printf ("[%s]: Invalid paramater!!\r\n", __func__);
        return;
    }

    list_add (entry, head, head->next);
    return;
}

static inline void 
list_add_tail (struct list_head *entry, struct list_head *head)
{
    if ((entry == NULL) || (head == NULL))
    {
        printf ("[%s]: Invalid paramater!!\r\n", __func__);
        return;
    }

    list_add (entry, head->prev, head);
    return;
}

static inline void 
list_del (struct list_head *prev, struct list_head *next)
{
    if ((prev == NULL) || (next == NULL))
    {
        printf ("[%s]: Invalid paramater!!\r\n", __func__);
        return;
    }

    next->prev = prev;
    prev->next = next;
    return;
}

static inline void 
list_del_init (struct list_head *entry)
{
    if (entry == NULL)
    {
        printf ("[%s]: Invalid paramater!!\r\n", __func__);
        return;
    }

    list_del (entry->prev, entry->next);
    INIT_LIST_HEAD (entry);
    return;
}

uint8_t *LispConstructMapRequest (uint32_t srcEid, uint32_t srcRloc,
                                  uint32_t dstEid, uint8_t dstEidPrefLen,
                                  tMapReqFlags flags, uint16_t *pMsgLen);

#endif /* __LISP_TDFS_H__ */
