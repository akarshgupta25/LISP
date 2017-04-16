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
extern tLispMSMRGlobals gLispMSMRGlob;

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
    }

    pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);
    return pBestCacheEntry;
}

int LispAddRlocEidMapEntry (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                            uint32_t recTtl)
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
        free (pMapCacheEntry);
        pMapCacheEntry = NULL;
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    memset (pMapCacheEntry, 0, sizeof (tEidPrefixRlocMap));
    pMapCacheEntry->eidPrefix.eid = eid & mask;
    pMapCacheEntry->eidPrefix.mask = mask;
    pMapCacheEntry->rloc = rloc;
    pMapCacheEntry->recTtl = recTtl;

    pthread_mutex_lock (&gLispGlob.itrMapCacheLock);
    list_add_head ((struct list_head *) pMapCacheEntry,
                   &gLispGlob.itrEidRlocMapCacheHead);
    pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);

    DumpLocalMapCache();

    return LISP_SUCCESS;
}

int LispDelRlocEidMapEntry (uint32_t eid, uint8_t prefLen)
{
    tEidPrefixRlocMap *pMapCacheEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          mask = 0;

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid prefix length!!\r\n", __func__);
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
        break;
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

int LispAddMobileEidEntry (uint32_t eid, uint8_t prefLen, uint8_t eidIfNum,
                           uint8_t *pSrcMacAddr)
{
    tMobileEidEntry   *pMobileEidEntry = NULL;
    uint32_t          mask = 0;

    pMobileEidEntry = (tMobileEidEntry *) malloc (sizeof (tMobileEidEntry));
    if (pMobileEidEntry == NULL)
    {
        printf ("Failed to allocate memory to Mobile EID entry!!\r\n");
        return LISP_FAILURE;
    }
    memset (pMobileEidEntry, 0, sizeof (tMobileEidEntry));

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid prefix length!!\r\n", __func__);
        free (pMobileEidEntry);
        pMobileEidEntry = NULL;
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    pMobileEidEntry->eidPrefix.eid = eid & mask;
    pMobileEidEntry->eidPrefix.mask = mask;
    pMobileEidEntry->rloc = gLispGlob.eidRlocMap[eidIfNum].rloc;
    pMobileEidEntry->eidIfNum = eidIfNum;
    memcpy (pMobileEidEntry->srcMacAddr, pSrcMacAddr, LISP_MAC_ADDR_LEN);

    pthread_mutex_lock (&gLispGlob.mobileEidLock);
    list_add_head ((struct list_head *) pMobileEidEntry,
                   &gLispGlob.mobileEidListHead);
    pthread_mutex_unlock (&gLispGlob.mobileEidLock);

    return LISP_SUCCESS;
}

tMobileEidEntry *LispGetMobileEidEntry (uint32_t eid, uint8_t eidIfNum)
{
    tMobileEidEntry   *pMobileEidEntry = NULL;
    tMobileEidEntry   *pBestMobileEidEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          bestEntryMask = 0;
    uint32_t          currEntryMask = 0;

    pthread_mutex_lock (&gLispGlob.mobileEidLock);

    list_for_each (pList, &gLispGlob.mobileEidListHead)
    {
        pMobileEidEntry = (tMobileEidEntry *) pList;

        if (pMobileEidEntry->eidIfNum != eidIfNum)
        {
            continue;
        }
        if ((eid & pMobileEidEntry->eidPrefix.mask) !=
            (pMobileEidEntry->eidPrefix.eid))
        {
            continue;
        }

        if (pBestMobileEidEntry == NULL)
        {
            pBestMobileEidEntry = pMobileEidEntry;
            continue;
        }

        bestEntryMask = ntohl (pBestMobileEidEntry->eidPrefix.mask);
        currEntryMask = ntohl (pMobileEidEntry->eidPrefix.mask);
        if (LispConvertMaskToPrefLen (currEntryMask) >
            LispConvertMaskToPrefLen (bestEntryMask))
        {
            pBestMobileEidEntry = pMobileEidEntry;
        }
    }

    pthread_mutex_unlock (&gLispGlob.mobileEidLock);
    return pBestMobileEidEntry;
}

int LispDelMobileEidEntry (uint32_t eid, uint8_t prefLen, uint8_t eidIfNum)
{
    tMobileEidEntry   *pMobileEidEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          mask = 0;

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid prefix length!!\r\n", __func__);
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    pthread_mutex_lock (&gLispGlob.mobileEidLock);

    list_for_each (pList, &gLispGlob.mobileEidListHead)
    {
        pMobileEidEntry = (tMobileEidEntry *) pList;

        if (pMobileEidEntry->eidIfNum != eidIfNum)
        {
            continue;
        }
        if ((pMobileEidEntry->eidPrefix.eid != (eid & mask)) ||
            (pMobileEidEntry->eidPrefix.mask != mask))
        {
            continue;
        }

        list_del_init ((struct list_head *) pMobileEidEntry);
        free (pMobileEidEntry);
        pMobileEidEntry = NULL;
        break;
    }

    pthread_mutex_unlock (&gLispGlob.mobileEidLock);
    return LISP_SUCCESS;
}

int LispAddMovedEidEntry (uint32_t eid, uint8_t prefLen)
{
    tMovedEidEntry   *pMovedEidEntry = NULL;
    uint32_t         mask = 0;

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid prefix length!!\r\n", __func__);
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    pMovedEidEntry = (tMovedEidEntry *) malloc (sizeof (tMovedEidEntry));
    if (pMovedEidEntry == NULL)
    {
        printf ("Failed to allocate memory to Moved EID entry!!\r\n");
        return LISP_FAILURE;
    }
    memset (pMovedEidEntry, 0, sizeof (tMovedEidEntry));

    pMovedEidEntry->eidPrefix.eid = eid & mask;
    pMovedEidEntry->eidPrefix.mask = mask;

    pthread_mutex_lock (&gLispGlob.movedEidLock);
    list_add_head ((struct list_head *) pMovedEidEntry,
                   &gLispGlob.movedEidListHead);
    pthread_mutex_unlock (&gLispGlob.movedEidLock);

    return LISP_SUCCESS;
}

tMovedEidEntry *LispGetMovedEidEntry (uint32_t eid)
{
    tMovedEidEntry    *pMovedEidEntry = NULL;
    tMovedEidEntry    *pBestMovedEidEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          currEntryMask = 0;
    uint32_t          bestEntryMask = 0;

    pthread_mutex_lock (&gLispGlob.movedEidLock);

    list_for_each (pList, &gLispGlob.movedEidListHead)
    {
        pMovedEidEntry = (tMovedEidEntry *) pList;
        if ((eid & pMovedEidEntry->eidPrefix.mask) !=
            (pMovedEidEntry->eidPrefix.eid))
        {
            continue;
        }

        if (pBestMovedEidEntry == NULL)
        {
            pBestMovedEidEntry = pMovedEidEntry;
            continue;
        }

        bestEntryMask = ntohl (pBestMovedEidEntry->eidPrefix.mask);
        currEntryMask = ntohl (pMovedEidEntry->eidPrefix.mask);
        if (LispConvertMaskToPrefLen (currEntryMask) >
            LispConvertMaskToPrefLen (bestEntryMask))
        {
            pBestMovedEidEntry = pMovedEidEntry;
        }
    }

    pthread_mutex_unlock (&gLispGlob.movedEidLock);
    return pBestMovedEidEntry;
}

int LispDelMovedEidEntry (uint32_t eid, uint8_t prefLen)
{
    tMovedEidEntry    *pMovedEidEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          mask = 0;

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid prefix length!!\r\n", __func__);
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    pthread_mutex_lock (&gLispGlob.movedEidLock);

    list_for_each (pList, &gLispGlob.movedEidListHead)
    {
        pMovedEidEntry = (tMovedEidEntry *) pList;
        if ((pMovedEidEntry->eidPrefix.eid != (eid & mask)) ||
            (pMovedEidEntry->eidPrefix.mask != mask))
        {
            continue;
        }

        list_del_init ((struct list_head *) pMovedEidEntry);
        free (pMovedEidEntry);
        pMovedEidEntry = NULL;
        break;
    }

    pthread_mutex_unlock (&gLispGlob.movedEidLock);
    return LISP_SUCCESS;
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

int LispItrUpdateEndSysArpEntry (uint32_t ipAddr, uint8_t *pMacAddr)
{
    tArpEntry   *pArpEntry = NULL;

    if (pMacAddr == NULL)
    {
        printf ("[%s]: Invalid Parameter!!\r\n", __func__);
        return LISP_FAILURE;
    }

    pArpEntry = LispGetEndSysArpEntry (ipAddr);
    if (pArpEntry == NULL)
    {
        pArpEntry = (tArpEntry *) malloc (sizeof (tArpEntry));
        if (pArpEntry == NULL)
        {
            printf ("Failed to allocate memory to ARP entry!!\r\n");
            return LISP_FAILURE;
        }
        memset (pArpEntry, 0, sizeof (tArpEntry));

        pArpEntry->ipAddr = ipAddr;
        memcpy (pArpEntry->macAddr, pMacAddr, LISP_MAC_ADDR_LEN);

        pthread_mutex_lock (&gLispGlob.arpListLock);
        list_add_tail ((struct list_head *) pArpEntry,
                       &gLispGlob.arpListHead);
        pthread_mutex_unlock (&gLispGlob.arpListLock);

        DumpItrArpList();
    }
    else if (memcmp (pArpEntry->macAddr, pMacAddr, LISP_MAC_ADDR_LEN))
    {
        pthread_mutex_lock (&gLispGlob.arpListLock);
        memcpy (pArpEntry->macAddr, pMacAddr, LISP_MAC_ADDR_LEN);
        pthread_mutex_unlock (&gLispGlob.arpListLock);

        DumpItrArpList();
    }

    return LISP_SUCCESS;
}

tArpEntry *LispGetEndSysArpEntry (uint32_t ipAddr)
{
    tArpEntry        *pArpEntry = NULL;
    struct list_head *pList = NULL;

    pthread_mutex_lock (&gLispGlob.arpListLock);

    list_for_each (pList, &gLispGlob.arpListHead)
    {
        pArpEntry = (tArpEntry *) pList;
        if (pArpEntry->ipAddr == ipAddr)
        {
            pthread_mutex_unlock (&gLispGlob.arpListLock);
            return pArpEntry;
        }
    }

    pthread_mutex_unlock (&gLispGlob.arpListLock);
    return NULL;
}

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
    printf ("\n");

    return;
}

void DumpMobileEidList (void)
{
    struct list_head   *pList = NULL;
    tMobileEidEntry    *pMobileEidEntry = NULL;
    struct in_addr     addr;

    printf ("Mobile EID List:\r\n");
    list_for_each (pList, &gLispGlob.mobileEidListHead)
    {
        pMobileEidEntry = (tMobileEidEntry *) pList;
        addr.s_addr = pMobileEidEntry->eidPrefix.eid;
        printf ("[]:%s / ", inet_ntoa (addr));
        addr.s_addr = pMobileEidEntry->eidPrefix.mask;
        printf ("%s\r\n", inet_ntoa (addr));
    }
    printf ("\n");

    return;
}

void DumpMovedEidList (void)
{
    struct list_head  *pList = NULL;
    tMovedEidEntry    *pMovedEidEntry = NULL;
    struct in_addr     addr;

    printf ("Moved EID List:\r\n");
    list_for_each (pList, &gLispGlob.movedEidListHead)
    {
        pMovedEidEntry = (tMovedEidEntry *) pList;
        addr.s_addr = pMovedEidEntry->eidPrefix.eid;
        printf ("[]:%s / ", inet_ntoa (addr));
        addr.s_addr = pMovedEidEntry->eidPrefix.mask;
        printf ("%s\r\n", inet_ntoa (addr));
    }
    printf ("\n");

    return;
}

void DumpItrArpList (void)
{
    tArpEntry        *pArpEntry = NULL;
    struct list_head *pList = NULL;
    char             buf[LISP_MAX_IP_STR_LEN];
    int              index = 0;

    printf ("ITR ARP List:\r\n");
    list_for_each (pList, &gLispGlob.arpListHead)
    {
        pArpEntry = (tArpEntry *) pList;
        printf ("%s , ", 
                inet_ntop (AF_INET, &pArpEntry->ipAddr, buf, sizeof (buf)));
        for (index = 0; index < LISP_MAC_ADDR_LEN; index++)
        {
            printf ("%x:", pArpEntry->macAddr[index]);
        }
        printf ("\n");
    }
    printf ("\n");

    return;
}

void DumpItrRxEndSysPkt (uint32_t srcEid, uint32_t dstEid)
{
    char  buf[LISP_MAX_IP_STR_LEN];
    
    printf ("ITR: Packet Rx from ");
    printf ("%s, to ", inet_ntop (AF_INET, &srcEid, buf, sizeof (buf)));
    printf ("%s\r\n", inet_ntop (AF_INET, &dstEid, buf, sizeof (buf)));
    return;
}

void DisplayItrMapCacheMissLog (uint32_t eid)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Map cache miss!! Sending Map-Request for ");
    printf ("EID %s..\r\n\n", inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    return;
}

void DisplayItrNegMapLog (uint32_t eid)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Negative mapping for EID %s!! Dropping packet..\r\n",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    return;
}

void DisplayItrTxLispEncpPktLog (uint32_t rloc)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Forwarding LISP encapsulated packet to RLOC %s..\r\n\n",
            inet_ntop (AF_INET, &rloc, buf, sizeof (buf)));
    return;
}

void DisplayItrMobileEidDiscLog (uint32_t eid)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Mobile EID %s discovered!! Sending Map-Register..\r\n",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    return;
}

void DisplayItrAddMapCacheLog (uint32_t eid, uint8_t prefLen, uint32_t rloc)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Received Map-Reply from Map-Server/Map-Resolver!!\r\n"
            "Adding mapping entry for ");
    printf ("EID %s/%d, ", inet_ntop (AF_INET, &eid, buf, sizeof (buf)), 
            prefLen);
    printf ("RLOC %s\r\n", inet_ntop (AF_INET, &rloc, buf, sizeof (buf)));
    return;
}

void DisplayItrSMReqLog (uint32_t eid)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Solicit Map-Request received!! Sending Map-Request for ");
    printf ("EID %s..\r\n", inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    return;
}

void DisplayEtrMovedEidLog (uint32_t eid, uint32_t rloc)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ETR: Packet received for moved EID %s!! ",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    printf ("Sending Solicit-Map-Request to ITR RLOC %s..\r\n", 
            inet_ntop (AF_INET, &rloc, buf, sizeof (buf)));
    return;
}

void DisplayEtrEndSysEidNotPresentLog (uint32_t eid)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ETR: Packet received for EID %s that is not present in "
            "LISP site!! Dropping packet..\r\n",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    return;
}

void DisplayEtrTxEndSysPktLog (uint32_t srcEid, uint32_t dstEid)
{
    char  buf[LISP_MAX_IP_STR_LEN];
    
    printf ("ETR: Forwarding end system packet from ");
    printf ("%s, to ", inet_ntop (AF_INET, &srcEid, buf, sizeof (buf)));
    printf ("%s\r\n\n", inet_ntop (AF_INET, &dstEid, buf, sizeof (buf)));
    return;
}

void DisplayEtrMapNotifyRxLog (uint32_t eid, uint8_t prefLen)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ETR: Map-Notify received for EID-prefix %s/%d!! ",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)), prefLen);
    printf ("Adding this to moved EID list..\r\n");
    return;
}

void DisplayEtrMapNotifyMobLog (uint32_t eid, uint8_t prefLen)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ETR: Map-Notify received for EID-prefix %s/%d!! ",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)), prefLen);
    printf ("Removing this from mobile EID list..\r\n");
    return;
}

void DisplayItrMovedEidReturnLog (uint32_t eid)
{
    char  buf[LISP_MAX_IP_STR_LEN];

    printf ("ITR: Packet received from moved EID %s!!\r\n",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)));
    printf ("Moved EID has returned to LISP site, sending Map-Register..\r\n");
    return;
}
