/********************************************************************
*
* Filename: pkt_util.c
*
* Description: This file contains the utility functions used by
*              LISP xTR
*
*******************************************************************/

#include "lisp_hdrs.h"

extern tLispGlobals gLispGlob;

int LispOpenEidSockets (void)
{
    int                sockFd = 0;
    uint8_t            eidIfNum = 0;
    struct sockaddr_ll socketBindAddr;
    struct ifreq       ifr;

    for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
    {
        sockFd = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sockFd < 0)
        {
            printf ("Failed to create raw socket for %s!!\r\n",
                    gLispGlob.pEidIfList[eidIfNum]);
            return LISP_FAILURE;
        }

        gLispGlob.rawSockFd[eidIfNum] = sockFd;

        memset (&ifr, 0, sizeof (ifr));
        strcpy (ifr.ifr_name, gLispGlob.pEidIfList[eidIfNum]);
        if (ioctl (sockFd, SIOCGIFINDEX, &ifr) < 0)
        {
            printf ("Invalid interface name %s!!\r\n",
                    gLispGlob.pEidIfList[eidIfNum]);
            return LISP_FAILURE;
        }

        memset (&socketBindAddr, 0, sizeof (socketBindAddr));
        socketBindAddr.sll_family = AF_PACKET;
        socketBindAddr.sll_protocol = htons(ETH_P_ALL);
        socketBindAddr.sll_ifindex = ifr.ifr_ifindex;
        if (bind (sockFd, (struct sockaddr *) &socketBindAddr,
                  sizeof(socketBindAddr)) < 0)
        {
            printf ("Failed to bind raw socket for %s!!\r\n",
                    gLispGlob.pEidIfList[eidIfNum]);
            return LISP_FAILURE;
        }
    }

    return LISP_SUCCESS;
}

int LispOpenDataSockets (void)
{
    int                sockFd = 0;
    struct sockaddr_in sockAddr;

    /* Create UDP socket to Tx LISP encapsulated traffic */
    sockFd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        printf ("Failed to create UDP socket to Tx LISP traffic!!\r\n");
        return LISP_FAILURE;
    }
    gLispGlob.txLispPktSock = sockFd;

    /* Create UDP socket to Rx LISP encapsulated traffic */
    sockFd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        printf ("Failed to create UDP socket to Rx LISP traffic!!\r\n");
        return LISP_FAILURE;
    }
    gLispGlob.rxLispPktSock = sockFd;

    memset (&sockAddr, 0, sizeof (sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = htonl (INADDR_ANY);
    sockAddr.sin_port = htons (LISP_DATA_PKT_UDP_PORT);
    if (bind (sockFd, (struct sockaddr *) &sockAddr, sizeof (sockAddr)) < 0)
    {
        printf ("Failed to create UDP socket to Rx LISP traffic!!\r\n");
        return LISP_FAILURE;
    }
    
    return LISP_SUCCESS;
}

int LispOpenControlSockets (void)
{
    int                sockFd = 0;
    struct sockaddr_in sockAddr;

    /* Create UDP socket to Tx control messages to Map-Server/Map-Resolver */
    sockFd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        printf ("Failed to create UDP socket to Tx control msgs!!\r\n");
        return LISP_FAILURE;
    }
    gLispGlob.txLispCntrlSock = sockFd;

    /* Create UDP socket to Rx LISP control messages */
    sockFd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        printf ("Failed to create UDP socket to Rx control msgs!!\r\n");
        return LISP_FAILURE;
    }
    gLispGlob.rxLispCntrlSock = sockFd;

    memset (&sockAddr, 0, sizeof (sockAddr));
    sockAddr.sin_family = AF_INET;
    sockAddr.sin_addr.s_addr = htonl (INADDR_ANY);
    sockAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    if (bind (sockFd, (struct sockaddr *) &sockAddr, sizeof (sockAddr)) < 0)
    {
        printf ("Failed to create UDP socket to Rx control msgs!!\r\n");
        return LISP_FAILURE;
    }
    
    return LISP_SUCCESS;
}

int LispConvertPrefixLenToMask (uint8_t prefLen, uint32_t *pMask)
{
    uint8_t    bit = 0;
    uint32_t   mask = 0;

    *pMask = 0;
    if (prefLen > LISP_MAX_PREF_LEN)
    {
        printf ("Prefix length exceeds %d!!\r\n", LISP_MAX_PREF_LEN);
        return LISP_FAILURE;
    }

    for (bit = 0; bit < LISP_MAX_PREF_LEN - prefLen; bit++)
    {
        mask |= (0x1 << bit);
    }
    mask = (~mask);

    *pMask = mask;
    return LISP_SUCCESS;
}

int LispGetIfIpAddr (uint8_t eidIfNum, uint32_t *pIfAddr)
{
    struct ifreq ifr;
    int          sockFd = 0;

    memset (&ifr, 0, sizeof (ifr));
    ifr.ifr_addr.sa_family = AF_INET;
    strcpy (ifr.ifr_name, gLispGlob.pEidIfList[eidIfNum]);

    sockFd = gLispGlob.rawSockFd[eidIfNum];
    if (ioctl (sockFd, SIOCGIFADDR, &ifr) < 0)
    {
        return LISP_FAILURE;
    }

    *pIfAddr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
    return LISP_SUCCESS;
}

int LispGetEndSysMacAddr (uint32_t ipAddr, uint8_t eidIfNum, uint8_t *pMacAddr)
{
    struct arpreq       areq;
    struct sockaddr_in  *sin = NULL;
    int                 sockFd = 0;

    sockFd = gLispGlob.rxLispPktSock;

    memset (&areq, 0, sizeof (areq));
    sin = (struct sockaddr_in *) &areq.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ipAddr;
    sin = (struct sockaddr_in *) &areq.arp_ha;
    sin->sin_family = ARPHRD_ETHER;
    strcpy (areq.arp_dev, gLispGlob.pEidIfList[eidIfNum]);

    if (ioctl (sockFd, SIOCGARP, &areq) < 0)
    {
        perror ("ARP ioctl");
        return LISP_FAILURE;
    }

    memcpy (pMacAddr, areq.arp_ha.sa_data, LISP_MAC_ADDR_LEN);
    return LISP_SUCCESS;
}

int LispGetIfMacAddr (uint8_t eidIfNum, uint8_t *pIfMacAddr)
{
    struct ifreq ifr;
    int          sockFd = 0;

    sockFd = gLispGlob.rxLispPktSock;

    memset (&ifr, 0, sizeof (ifr));
    strcpy (ifr.ifr_name, gLispGlob.pEidIfList[eidIfNum]);
    if (ioctl (sockFd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror ("IfMacAddr ioctl");
        return LISP_FAILURE;
    }

    memcpy (pIfMacAddr, ifr.ifr_hwaddr.sa_data, LISP_MAC_ADDR_LEN);
    return LISP_SUCCESS;
}

tEidPrefixRlocMap *LispGetEidToRlocMap (uint32_t eid)
{
    struct list_head  *pList = NULL;
    struct list_head  *pItrMapCacheHead = NULL;
    tEidPrefixRlocMap *pMapCacheEntry = NULL;
    tEidPrefixRlocMap *pBestCacheEntry = NULL;
    uint32_t           bestEntryMask = 0;
    uint32_t           cacheEntryMask = 0;

    pthread_mutex_lock (&gLispGlob.itrMapCacheLock);

    pItrMapCacheHead = &gLispGlob.itrEidRlocMapCacheHead;
    list_for_each (pList, pItrMapCacheHead)
    {
        pMapCacheEntry = (tEidPrefixRlocMap *) pList;
        if ((eid & pMapCacheEntry->eidPrefix.mask) !=
            (pMapCacheEntry->eidPrefix.eid))
        {
            continue;
        }

        if (pBestCacheEntry == NULL)
        {
            pBestCacheEntry = pMapCacheEntry;
            continue;
        }

        bestEntryMask = ntohl (pBestCacheEntry->eidPrefix.mask);
        cacheEntryMask = ntohl (pMapCacheEntry->eidPrefix.mask);
        if (LispConvertMaskToPrefLen (cacheEntryMask) >
            LispConvertMaskToPrefLen (bestEntryMask))
        {
            pBestCacheEntry = pMapCacheEntry;
        }
#if 0
        if (LispConvertMaskToPrefLen (pMapCacheEntry->eidPrefix.mask) >
            LispConvertMaskToPrefLen (pBestCacheEntry->eidPrefix.mask))
        {
            pBestCacheEntry = pMapCacheEntry;
        }
#endif
    }

    pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);
    return pBestCacheEntry;
}

int LispAddRlocEidMapEntry (uint32_t eid, uint8_t prefLen, uint32_t rloc)
{
    tEidPrefixRlocMap *pMapCacheEntry = NULL;
    uint32_t          mask = 0;

    pMapCacheEntry = (tEidPrefixRlocMap *) malloc (sizeof (tEidPrefixRlocMap));
    if (pMapCacheEntry == NULL)
    {
        printf ("Failed to allocate memory to ITR local cache entry!!\r\n");
        return LISP_FAILURE;
    }

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    memset (pMapCacheEntry, 0, sizeof (tEidPrefixRlocMap));
    pMapCacheEntry->eidPrefix.eid = eid & mask;
    pMapCacheEntry->eidPrefix.mask = mask;
    pMapCacheEntry->rloc = rloc;

    pthread_mutex_lock (&gLispGlob.itrMapCacheLock);
    list_add_head ((struct list_head *) pMapCacheEntry,
                   &gLispGlob.itrEidRlocMapCacheHead);
    pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);

    return LISP_SUCCESS;
}

int LispDelRlocEidMapEntry (uint32_t eid, uint8_t prefLen)
{
    tEidPrefixRlocMap *pMapCacheEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          mask = 0;

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    pthread_mutex_lock (&gLispGlob.itrMapCacheLock);

    /* Delete entry with same EID-prefix and prefix length */
    list_for_each (pList, &gLispGlob.itrEidRlocMapCacheHead)
    {
        pMapCacheEntry = (tEidPrefixRlocMap *) pList;
        if ((pMapCacheEntry->eidPrefix.eid != (eid & mask)) ||
            (pMapCacheEntry->eidPrefix.mask != mask))
        {
            continue;
        }

        list_del_init ((struct list_head *) pMapCacheEntry);
        free (pMapCacheEntry);
        pMapCacheEntry = NULL;
    }

    pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);
    return LISP_SUCCESS;
}

uint8_t LispConvertMaskToPrefLen (uint32_t mask)
{
    uint8_t   bit = 0;

    for (bit = 0; bit < LISP_MAX_PREF_LEN; bit++)
    {
        if (mask & (0x1 << bit))
        {
            break;
        }
    }

    return (LISP_MAX_PREF_LEN - bit);
}

void *LispGetMovedEidEntry (uint32_t eid)
{
    return NULL;
}

void *LispGetMobileEidEntry (uint32_t eid)
{
    return NULL;
}

uint8_t *LispConstructMapRequest (uint32_t srcEid, uint32_t srcRloc,
                                  uint32_t dstEid, uint8_t dstEidPrefLen,
                                  tMapReqFlags flags, uint16_t *pMsgLen)
{
    tMapReqHdr     *pMapReqMsg = NULL;
    tMapReqRec     *pMapReqRec = NULL;
    uint16_t       mapReqMsgLen = 0;

    if (pMsgLen == NULL)
    {
        printf ("Invalid Parameter!!\r\n");
        return NULL;
    }

    mapReqMsgLen = sizeof (tMapReqHdr) + sizeof (tMapReqRec);
    pMapReqMsg = (tMapReqHdr *) malloc (mapReqMsgLen);
    if (pMapReqMsg == NULL)
    {
        printf ("Failed to allocate memory to Map Request msg!!\r\n");
        return NULL;
    }
    memset (pMapReqMsg, 0, mapReqMsgLen);

    pMapReqMsg->smrBit = flags.smrBit;
    pMapReqMsg->probeBit = flags.probeBit;
    pMapReqMsg->mapDataBit = flags.mapDataBit;
    pMapReqMsg->authBit = flags.authBit;
    pMapReqMsg->smrInvokBit = flags.smrInvokBit;
    pMapReqMsg->pitrBit = flags.pitrBit;

    pMapReqMsg->type = LISP_MAP_REQ_MSG;
    pMapReqMsg->itrRlocCount = 0;
    pMapReqMsg->recordCount = 1;

    pMapReqMsg->srcEidAfi = htons (LISP_IPV4_AFI);
    srcEid = ntohl (srcEid);
    pMapReqMsg->srcEidHi = htons ((srcEid >> 16) & 0xFFFF);
    pMapReqMsg->srcEidLo = htons (srcEid & 0xFFFF);

    pMapReqMsg->itrRlocAfi = htons (LISP_IPV4_AFI);
    srcRloc = ntohl (srcRloc);
    pMapReqMsg->itrRlocHi = htons ((srcRloc >> 16) & 0xFFFF);
    pMapReqMsg->itrRlocLo = htons (srcRloc & 0xFFFF);

    pMapReqRec = (tMapReqRec *)
                 (((uint8_t *) pMapReqMsg) + sizeof (tMapReqHdr));

    pMapReqRec->dstEidPrefLen = dstEidPrefLen;
    pMapReqRec->dstEidPrefAfi = htons (LISP_IPV4_AFI);
    pMapReqRec->dstEid = dstEid;

    *pMsgLen = mapReqMsgLen;
    return ((uint8_t *) pMapReqMsg);
}

#if 0
void TestDllAddDel (void)
{
    struct list_head head;
    struct list_head *list = NULL;
    tEndSysMovedEid  *entry = NULL;

    INIT_LIST_HEAD (&head);

    entry = (tEndSysMovedEid  *) malloc (sizeof (tEndSysMovedEid));
    if (entry == NULL)
    {
        printf ("[%s]: Malloc failed!!\r\n", __func__);
        return;
    }
    memset (entry, 0, sizeof (tEndSysMovedEid));
    entry->eid = 10;
    list_add_head (&(entry->list), &head);

    entry = (tEndSysMovedEid  *) malloc (sizeof (tEndSysMovedEid));
    if (entry == NULL)
    {
        printf ("[%s]: Malloc failed!!\r\n", __func__);
        return;
    }
    memset (entry, 0, sizeof (tEndSysMovedEid));
    entry->eid = 20;
    list_add_head (&(entry->list), &head);

    entry = (tEndSysMovedEid  *) malloc (sizeof (tEndSysMovedEid));
    if (entry == NULL)
    {
        printf ("[%s]: Malloc failed!!\r\n", __func__);
        return;
    }
    memset (entry, 0, sizeof (tEndSysMovedEid));
    entry->eid = 30;
    list_add_head (&(entry->list), &head);

    entry = (tEndSysMovedEid  *) malloc (sizeof (tEndSysMovedEid));
    if (entry == NULL)
    {
        printf ("[%s]: Malloc failed!!\r\n", __func__);
        return;
    }
    memset (entry, 0, sizeof (tEndSysMovedEid));
    entry->eid = 40;
    list_add_head (&(entry->list), &head);

    list_for_each (list, &head)
    {
        entry = (tEndSysMovedEid *)list;
        printf ("eid:%u\r\n", entry->eid);
    }

    list_for_each (list, &head)
    {
        list_del_init (list);
        free (list);
        list = NULL;
        break;
    }

    list_for_each (list, &head)
    {
        entry = (tEndSysMovedEid *)list;
        printf ("eid:%u\r\n", entry->eid);
    }

    list_for_each (list, &head)
    {
        list_del_init (list);
        free (list);
        list = NULL;
        break;
    }

    list_for_each (list, &head)
    {
        entry = (tEndSysMovedEid *)list;
        printf ("eid:%u\r\n", entry->eid);
    }

    return;
}
#endif

/* Debug functions */
void DumpPacket (char *au1Packet, int len)
{
    unsigned int u4ByteCount = 0;
    unsigned int u4Length = len;
    char         tempDataLow = 0;
    char         tempDataHigh = 0;

    for (u4ByteCount = 0; u4ByteCount < u4Length; u4ByteCount++)
    {
        if ((u4ByteCount % 16) == 0)
        {
            printf ("\n");
        }
        
        tempDataLow = (au1Packet[u4ByteCount] >> 4) & 0xF;
        tempDataHigh = au1Packet[u4ByteCount] & 0xF;
        if ((tempDataLow >= 0) && (tempDataLow <= 0x9))
        {
            tempDataLow += 48;
        }
        else if ((tempDataLow >= 0xA) && (tempDataLow <= 0xF))
        {
            tempDataLow += 87;
        }
        if ((tempDataHigh >= 0) && (tempDataHigh <= 0x9))
        {
            tempDataHigh += 48;
        }
        else if ((tempDataHigh >= 0xA) && (tempDataHigh <= 0xF))
        {
            tempDataHigh += 87;
        }
        
        printf ("%c%c ", tempDataLow, tempDataHigh);
    }
    printf ("\n");
   
    return;
}

void PrintUsage (void)
{
    printf ("Usage: ./LISP_xTR { options }\r\n"
            "Options:\r\n"
            "%s <eth1,eth2,..>: Interfaces connected to end systems\r\n"
            "%s <MS/MR IP address>: IP address of Map-Server/Map-Resolver\r\n"
            "%s <EID-prefix,RLOC>: EID-prefix to RLOC association\r\n",
            LISP_EID_IF_CMD_OPT, LISP_MSMR_IP_CMD_OPT, LISP_EID_TO_RLOC_CMD_OPT);
    return;
}

void DumpCmdLineArg (void)
{
    struct in_addr mapSRIpAddr;
    struct in_addr eid;
    struct in_addr eidMask;
    struct in_addr rloc;
    uint8_t        index = 0;

    printf ("Number of EID Interfaces:%d\r\n", gLispGlob.numEidIf);
    for (index = 0; index < gLispGlob.numEidIf; index++)
    {
        eid.s_addr = gLispGlob.eidRlocMap[index].eidPrefix.eid;
        eidMask.s_addr = gLispGlob.eidRlocMap[index].eidPrefix.mask;
        rloc.s_addr = gLispGlob.eidRlocMap[index].rloc;
#if 0
        prefLen = gLispGlob.eidRlocMap[index].eidPrefix.prefLen;
#endif
        printf ("[%d]:%s\r\n", index+1, gLispGlob.pEidIfList[index]);
#if 0
        printf ("%s/%d,", inet_ntoa (eid), prefLen);
#endif
        printf ("%s/", inet_ntoa (eid));
        printf ("%s,", inet_ntoa (eidMask));
        printf ("%s\r\n", inet_ntoa (rloc));
    }

    mapSRIpAddr.s_addr = gLispGlob.mapSRIpAddr;
    printf ("Map-Server/Resolver IP Address:%s\r\n",
            inet_ntoa (mapSRIpAddr));

    return;
}

void DumpSockFd (void)
{
    uint8_t eidIfNum = 0;

    printf ("\nSocket File Descriptor Information:\r\n");
    printf ("Raw Sockets:\r\n");
    for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
    {
        printf ("[%s]:%d\r\n", gLispGlob.pEidIfList[eidIfNum], 
                gLispGlob.rawSockFd[eidIfNum]);
    }

    printf ("UDP Tx Data Socket:%d\r\n", gLispGlob.txLispPktSock);
    printf ("UDP Rx Data Socket:%d\r\n", gLispGlob.rxLispPktSock);
    printf ("UDP Tx Control Socket:%d\r\n", gLispGlob.txLispCntrlSock);
    printf ("UDP Rx Control Socket:%d\r\n", gLispGlob.rxLispCntrlSock);

    return;
}

void DumpLocalMapCache (void)
{
    struct list_head  *pList = NULL;
    struct list_head  *pItrMapCacheHead = NULL;
    tEidPrefixRlocMap *pMapCacheEntry = NULL;
    struct in_addr    addr;

    printf ("Local Map Cache: \r\n");
    pItrMapCacheHead = &gLispGlob.itrEidRlocMapCacheHead;
    list_for_each (pList, pItrMapCacheHead)
    {
        pMapCacheEntry = (tEidPrefixRlocMap *) pList;
        addr.s_addr = pMapCacheEntry->eidPrefix.eid;
        printf ("[]:%s / ", inet_ntoa (addr));
        addr.s_addr = pMapCacheEntry->eidPrefix.mask;
        printf ("%s , ", inet_ntoa (addr));
        addr.s_addr = pMapCacheEntry->rloc;
        printf ("%s\r\n", inet_ntoa (addr));
    }

    return;
}