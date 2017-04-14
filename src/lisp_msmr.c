/********************************************************************
*
* Filename: lisp_msmr.c
*
* Description: This file contains LISP Map-Server/Map-Resolver code
*
********************************************************************/

#include "lisp_hdrs.h"

tLispMSMRGlobals gLispMSMRGlob;

int main (int argc, char *argv[])
{
    struct sockaddr_in  srcAddr;
    int                 srcAddrLen = 0;
    uint8_t             cntrlPkt[LISP_MTU_SIZE];
    uint16_t            cntrlPktLen = 0;
    uint8_t             lispMsgType = 0;

    if (LispMSMRInit() != LISP_SUCCESS)
    {
        CleanupMSMR();
        return LISP_FAILURE;
    }

    while (1)
    {
        memset (cntrlPkt, 0, sizeof (cntrlPkt));
        memset (&srcAddr, 0, sizeof (srcAddr));
        srcAddrLen = sizeof (srcAddr);
        cntrlPktLen = recvfrom (gLispMSMRGlob.lispCntrlSock, cntrlPkt,
                                sizeof (cntrlPkt), 0,
                                (struct sockaddr *) &srcAddr,
                                (socklen_t *) &srcAddrLen);
        if (cntrlPktLen <= 0)
        {
            printf ("Failed to Rx LISP control packet!!\r\n");
            continue;
        }

        lispMsgType = ((cntrlPkt[0] >> 4) & 0xF);
        switch (lispMsgType)
        {
            case LISP_MAP_REQ_MSG:
                LispMSMRProcessMapRequest (cntrlPkt, cntrlPktLen,
                                           srcAddr, srcAddrLen);
                break;

            case LISP_MAP_REG_MSG:
                LispMSMRProcessMapRegister (cntrlPkt, cntrlPktLen,
                                            srcAddr, srcAddrLen);
                break;

            default:
                printf ("Control message other than Map-Request and "
                        "Map-Register Rx!!\r\n");
                continue;
        }
    }

    CleanupMSMR();
    return LISP_SUCCESS;
}

int LispMSMRInit (void)
{
    memset (&gLispMSMRGlob, 0, sizeof (gLispMSMRGlob));

    /* Create UDP socket for LISP control messages */
    if (LispMSMROpenControlSocket() != LISP_SUCCESS)
    {
        printf ("Failed to create MSMR UDP socket!!\r\n");
        return LISP_FAILURE;
    }

    /* Initialize MSMR Eid Rloc map database */
    INIT_LIST_HEAD (&gLispMSMRGlob.eidRlocMapDbHead);

    return LISP_SUCCESS;
}

void CleanupMSMR (void)
{
    /* EID If List, sockets, threads */
    return;
}

int LispMSMROpenControlSocket (void)
{
    struct sockaddr_in  msmrAddr;
    int                 sockFd = 0;

    sockFd = socket (AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0)
    {
        perror ("Open MSMR UDP socket");
        return LISP_FAILURE;
    }

    memset (&msmrAddr, 0, sizeof (msmrAddr));
    msmrAddr.sin_family = AF_INET;
    msmrAddr.sin_addr.s_addr = htonl (INADDR_ANY);
    msmrAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    if (bind (sockFd, (struct sockaddr *) &msmrAddr, sizeof (msmrAddr)) < 0)
    {
        perror ("Bind MSMR UDP socket");
        return LISP_FAILURE;
    }

    gLispMSMRGlob.lispCntrlSock = sockFd;
    return LISP_SUCCESS;
}

int LispMSMRProcessMapRequest (uint8_t *pCntrlPkt, uint16_t cntrlPktLen,
                               struct sockaddr_in itrAddr, int itrAddrLen)
{
    tMapReqHdr        *pMapReqMsg = NULL;
    tMapReqRec        *pMapReqRec = NULL;
    tEidPrefixRlocMap *pMapDbEntry = NULL;
    uint32_t          dstEid = 0;
    uint32_t          mask = 0;

    if (pCntrlPkt == NULL)
    {
        printf ("[%s]: Invalid Parameter!!\r\n", __func__);
        return LISP_FAILURE;
    }
    pMapReqMsg = (tMapReqHdr *) pCntrlPkt;

    if (pMapReqMsg->recordCount == 0)
    {
        printf ("Map-Request message does not contain Record!!\r\n");
        return LISP_SUCCESS;
    }
    pMapReqRec = (tMapReqRec *)
                 (((uint8_t *) pMapReqMsg) + sizeof (tMapReqHdr));

    if (LispConvertPrefixLenToMask (pMapReqRec->dstEidPrefLen, &mask) 
        != LISP_SUCCESS)
    {
        printf ("Invalid prefix length Rx in Map-Request msg!!\r\n");
        return LISP_FAILURE;
    }
    mask = htonl (mask);
    dstEid = pMapReqRec->dstEid & mask;

    pMapDbEntry = LispMSMRGetEidToRlocMap (dstEid);
    if (pMapDbEntry == NULL)
    {
        printf ("Mapping does not exist!! Sending negative Map-Reply..\r\n");
        /* NOTE: Send negative Map-Reply message */
        return LISP_SUCCESS;
    }

    if (pMapDbEntry->isProxySet != LISP_TRUE)
    {
        printf ("Forwarding Map-Request to appropriate ETR..\r\n");
        /* NOTE: Forward message to appropriate ETR */
        return LISP_SUCCESS;
    }
    if (pMapDbEntry->rloc == 0)
    {
        printf ("RLOC not present for requested EID-prefix!! "
                "Sending negative Map-Reply..\r\n");
        /* NOTE: Send negative Map-Reply message */
        return LISP_SUCCESS;
    }

    DisplayMapReqMapRepLog (dstEid, pMapReqRec->dstEidPrefLen,
                            pMapDbEntry->eidPrefix.eid, 
                            pMapDbEntry->eidPrefix.mask,
                            pMapDbEntry->rloc);

    /* Mapping found in database, send Map-Reply */
    LispSendMapReply (pMapDbEntry->eidPrefix.eid, pMapDbEntry->eidPrefix.mask,
                      pMapDbEntry->rloc, pMapDbEntry->recTtl, itrAddr,
                      itrAddrLen);

    return LISP_SUCCESS;
}

int LispMSMRProcessMapRegister (uint8_t *pCntrlPkt, uint16_t cntrlPktLen,
                                struct sockaddr_in etrAddr, int etrAddrLen)
{
    tMapRegHdr        *pMapRegMsg = NULL;
    tRlocRecord       *pRlocRec = NULL;
    tRlocLoc          *pLoc = NULL;
    tEidPrefixRlocMap *pCurrMapDbEntry = NULL;
    uint32_t          recTtl = 0;
    uint32_t          eid = 0;
    uint32_t          rloc = 0;
    uint32_t          mask = 0;
    uint8_t           isProxySet = LISP_FALSE;
    uint8_t           isMapNotifySet = LISP_FALSE;

    if (pCntrlPkt == NULL)
    {
        printf ("[%s]: Invalid Parameter!!\r\n", __func__);
        return LISP_FAILURE;
    }
    pMapRegMsg = (tMapRegHdr *) pCntrlPkt;

    if (pMapRegMsg->proxyBit == 1)
    {
        isProxySet = LISP_TRUE;
    }
    if (pMapRegMsg->mapNotBit == 1)
    {
        isMapNotifySet = LISP_TRUE;
    }
    if (pMapRegMsg->recordCount == 0)
    {
        printf ("Map-Register message does not contain Record!!\r\n");
        if (isMapNotifySet == LISP_TRUE)
        {
            /* NOTE: Check if ACK needs to be sent to ETR if Map-Notify is 
             * set */
        }
        return LISP_SUCCESS;
    }

    pRlocRec = (tRlocRecord *)
               (((uint8_t *) pMapRegMsg) + sizeof (tMapRegHdr));
    recTtl = pRlocRec->recTtl;
    if (pRlocRec->locCount == 0)
    {
        printf ("Map-Register message does not contain RLOCs!!\r\n");
        rloc = 0;
    }
    else
    {
        pLoc = (tRlocLoc *)
               (((uint8_t *) pRlocRec) + sizeof (tRlocRecord));
        rloc = pLoc->rloc;
    }

    if (LispConvertPrefixLenToMask (pRlocRec->eidPrefLen, &mask) 
        != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid mask!!\r\n", __func__);
        return LISP_FAILURE;
    }
    mask = htonl (mask);
    eid = pRlocRec->eidPrefix & mask;

    /* If EID-prefix to register does not belong to same subnet as
     * EID-prefix previously registered by ETR then the destination
     * EID is a mobile device. Send Map-Notify message to previous
     * RLOC associated with this destination EID */
    pCurrMapDbEntry = LispMSMRGetEidToRlocMap (eid);
    if ((pCurrMapDbEntry != NULL) && (pCurrMapDbEntry->rloc != rloc))
    {
        DisplayMobileEidMapNotifyLog (eid, pRlocRec->eidPrefLen,
                                      pCurrMapDbEntry->etrAddr);
        LispSendMapNotify (eid, pRlocRec->eidPrefLen, rloc, 
                           pCurrMapDbEntry->recTtl, pCurrMapDbEntry->etrAddr);
        LispMSMRDelRlocEidMapEntry (eid, pRlocRec->eidPrefLen);
    }
    
    /* Add entry only if addition of entry does not create overlapping
     * EID-prefix to RLOC mapping. This is the case when a mobile
     * device comes back to its original LISP site. In such a case,
     * no need to add a separate mapping for the device */
    pCurrMapDbEntry = LispMSMRGetEidToRlocMap (eid);
    if ((pCurrMapDbEntry == NULL) || (pCurrMapDbEntry->rloc != rloc))
    {
        LispMSMRAddRlocEidMapEntry (eid, pRlocRec->eidPrefLen, rloc, recTtl,
                                    isProxySet, etrAddr.sin_addr.s_addr);
    }

    if (isMapNotifySet == LISP_TRUE)
    {
        /* NOTE: Send Map-Notify to ETR */
    }
   
    return LISP_SUCCESS;
}

int LispSendMapReply (uint32_t eid, uint32_t mask, uint32_t rloc, uint32_t ttl,
                      struct sockaddr_in dstAddr, int dstAddrLen)
{
    uint8_t   *pMapRepMsg = NULL;
    uint16_t  mapRepMsgLen = 0;
    uint8_t   prefLen = 0;

    prefLen = LispConvertMaskToPrefLen (ntohl (mask));

    pMapRepMsg = LispConstructMapReply (eid, prefLen, rloc, ttl,
                                        &mapRepMsgLen);
    if (pMapRepMsg == NULL)
    {
        printf ("Failed to construct Map-Reply message!!\r\n");
        return LISP_FAILURE;
    }

    sendto (gLispMSMRGlob.lispCntrlSock, pMapRepMsg, mapRepMsgLen, 0,
            (struct sockaddr *) &dstAddr, dstAddrLen);

    free (pMapRepMsg);
    pMapRepMsg = NULL;
    return LISP_SUCCESS;
}

uint8_t *LispConstructMapReply (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                                uint32_t ttl, uint16_t *pMapRepMsgLen)
{
    tMapRepHdr   *pMapRepMsg = NULL;
    tRlocRecord  *pRlocRec = NULL;
    tRlocLoc     *pLoc = NULL;
    uint16_t     mapRepMsgLen = 0;
    uint16_t     locLen = 0;

    if (pMapRepMsgLen == NULL)
    {
        printf ("[%s]: Invalid Parameter!!\r\n", __func__);
        return NULL;
    }

    locLen = (rloc != 0) ? sizeof (tRlocLoc) : 0;
    mapRepMsgLen = sizeof (tMapRepHdr) + sizeof (tRlocRecord) + locLen;
    *pMapRepMsgLen = mapRepMsgLen;

    pMapRepMsg = (tMapRepHdr *) malloc (mapRepMsgLen);
    if (pMapRepMsg == NULL)
    {
        printf ("Failed to allocate memory to Map-Reply message!!\r\n");
        return NULL;
    }
    memset (pMapRepMsg, 0, sizeof (mapRepMsgLen));

    pMapRepMsg->type = LISP_MAP_REP_MSG;
    pMapRepMsg->recordCount = 1;

    pRlocRec = (tRlocRecord *)
               (((uint8_t *) pMapRepMsg) + sizeof (tMapRepHdr));
    pRlocRec->recTtl = ttl;
    pRlocRec->eidPrefLen = prefLen;
    pRlocRec->mapVerNum = htons (LISP_DEF_MAP_VER_NUM);
    pRlocRec->eidPrefixAfi = htons (LISP_IPV4_AFI);
    pRlocRec->eidPrefix = eid;

    if (rloc == 0)
    {
        return ((uint8_t *) pMapRepMsg);
    }
    pRlocRec->locCount = 1;

    pLoc = (tRlocLoc *)
           (((uint8_t *) pRlocRec) + sizeof (tRlocRecord));
    pLoc->rlocAfi = htons (LISP_IPV4_AFI);
    pLoc->rloc = rloc;

    return ((uint8_t *) pMapRepMsg);
}

int LispSendMapNotify (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                       uint32_t recTtl, uint32_t etrAddr)
{
    struct sockaddr_in  dstAddr;
    tMapNotifyHdr       *pMapNotifyMsg = NULL;
    tRlocRecord         *pRlocRec = NULL;
    tRlocLoc            *pLoc = NULL;
    int                 mapNotifyMsgLen = 0;

    mapNotifyMsgLen = sizeof (tMapNotifyHdr) + sizeof (tRlocRecord) +
                      sizeof (tRlocLoc);
    pMapNotifyMsg = (tMapNotifyHdr *) malloc (mapNotifyMsgLen);
    if (pMapNotifyMsg == NULL)
    {
        printf ("Failed to allocate memory to Map-Notify message!!\r\n");
        return LISP_FAILURE;
    }
    memset (pMapNotifyMsg, 0, mapNotifyMsgLen);

    pMapNotifyMsg->type = LISP_MAP_NOTIFY_MSG;
    pMapNotifyMsg->recordCount = 1;
    pMapNotifyMsg->authDataLen = htons (LISP_DEF_AUTH_DATA_LEN);

    pRlocRec = (tRlocRecord *)
               (((uint8_t *) pMapNotifyMsg) + sizeof (tMapNotifyHdr));
    
    pRlocRec->recTtl = recTtl;
    pRlocRec->locCount = 1;
    pRlocRec->mapVerNum = htons (LISP_DEF_MAP_VER_NUM);
    pRlocRec->eidPrefLen = prefLen;
    pRlocRec->eidPrefixAfi = htons (LISP_IPV4_AFI);
    pRlocRec->eidPrefix = eid;

    pLoc = (tRlocLoc *)
           (((uint8_t *) pRlocRec) + sizeof (tRlocRecord));

    pLoc->rlocAfi = htons (LISP_IPV4_AFI);
    pLoc->rloc = rloc;

    memset (&dstAddr, 0, sizeof (dstAddr));
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_addr.s_addr = etrAddr;
    dstAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    sendto (gLispMSMRGlob.lispCntrlSock, pMapNotifyMsg, mapNotifyMsgLen, 0,
            (struct sockaddr *) &dstAddr, sizeof (dstAddr));

    return LISP_SUCCESS;
}

int LispMSMRAddRlocEidMapEntry (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                                uint32_t recTtl, uint8_t isProxySet, 
                                uint32_t etrAddr)
{
    tEidPrefixRlocMap *pMapDbEntry = NULL;
    uint32_t          mask = 0;

    pMapDbEntry = (tEidPrefixRlocMap *) malloc (sizeof (tEidPrefixRlocMap));
    if (pMapDbEntry == NULL)
    {
        printf ("Failed to allocate memory to database entry!!\r\n");
        return LISP_FAILURE;
    }

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid mask!!\r\n", __func__);
        free (pMapDbEntry);
        pMapDbEntry = NULL;
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    memset (pMapDbEntry, 0, sizeof (tEidPrefixRlocMap));
    pMapDbEntry->eidPrefix.eid = eid & mask;
    pMapDbEntry->eidPrefix.mask = mask;
    pMapDbEntry->rloc = rloc;
    pMapDbEntry->recTtl = recTtl;
    pMapDbEntry->isProxySet = isProxySet;
    pMapDbEntry->etrAddr = etrAddr;

    list_add_head ((struct list_head *) pMapDbEntry,
                   &gLispMSMRGlob.eidRlocMapDbHead);

    DumpMSMRMapDb();

    return LISP_SUCCESS;
}

int LispMSMRDelRlocEidMapEntry (uint32_t eid, uint8_t prefLen)
{
    tEidPrefixRlocMap *pMapDbEntry = NULL;
    struct list_head  *pList = NULL;
    uint32_t          mask = 0;

    if (LispConvertPrefixLenToMask (prefLen, &mask) != LISP_SUCCESS)
    {
        printf ("[%s]: Invalid mask!!\r\n", __func__);
        return LISP_FAILURE;
    }
    mask = htonl (mask);

    list_for_each (pList, &gLispMSMRGlob.eidRlocMapDbHead)
    {
        pMapDbEntry = (tEidPrefixRlocMap *) pList;
        if ((pMapDbEntry->eidPrefix.eid != (eid & mask)) ||
            (pMapDbEntry->eidPrefix.mask != mask))
        {
            continue;
        }        

        list_del_init ((struct list_head *) pMapDbEntry);
        free (pMapDbEntry);
        pMapDbEntry = NULL;
        break;
    }

    DumpMSMRMapDb();

    return LISP_SUCCESS;
}

tEidPrefixRlocMap *LispMSMRGetEidToRlocMap (uint32_t eid)
{
    struct list_head  *pList = NULL;
    tEidPrefixRlocMap *pCurrDbEntry = NULL;
    tEidPrefixRlocMap *pBestDbEntry = NULL;
    uint32_t           bestEntryMask = 0;
    uint32_t           currEntryMask = 0;

    list_for_each (pList, &gLispMSMRGlob.eidRlocMapDbHead)
    {
        pCurrDbEntry = (tEidPrefixRlocMap *) pList;
        if ((eid & pCurrDbEntry->eidPrefix.mask) !=
            (pCurrDbEntry->eidPrefix.eid))
        {
            continue;
        }

        if (pBestDbEntry == NULL)
        {
            pBestDbEntry = pCurrDbEntry;
            continue;
        }

        bestEntryMask = ntohl (pBestDbEntry->eidPrefix.mask);
        currEntryMask = ntohl (pCurrDbEntry->eidPrefix.mask);
        if (LispConvertMaskToPrefLen (currEntryMask) >
            LispConvertMaskToPrefLen (bestEntryMask))
        {
            pBestDbEntry = pCurrDbEntry;
        }
    }

    return pBestDbEntry;
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

void DumpMSMRMapDb (void)
{
    struct list_head  *pList = NULL;
    struct list_head  *pMapDbHead = NULL;
    tEidPrefixRlocMap *pMapDbEntry = NULL;
    struct in_addr    addr;

    printf ("Map-Server/Map-Resolver Mapping Database: \r\n");
    pMapDbHead = &gLispMSMRGlob.eidRlocMapDbHead;
    list_for_each (pList, pMapDbHead)
    {
        pMapDbEntry = (tEidPrefixRlocMap *) pList;
        addr.s_addr = pMapDbEntry->eidPrefix.eid;
        printf ("[]:%s / ", inet_ntoa (addr));
        addr.s_addr = pMapDbEntry->eidPrefix.mask;
        printf ("%s , ", inet_ntoa (addr));
        addr.s_addr = pMapDbEntry->rloc;
        printf ("%s , ", inet_ntoa (addr));
        addr.s_addr = pMapDbEntry->etrAddr;
        printf ("%s\r\n", inet_ntoa (addr));
    }
    printf ("\n");

    return;
}

void DisplayMapReqMapRepLog (uint32_t srcEid, uint8_t srcPrefLen, 
                             uint32_t dstEid, uint32_t dstEidMask, 
                             uint32_t rloc)
{
    char     buf[LISP_MAX_IP_STR_LEN];
    uint8_t  dstPrefLen = 0;

    dstEidMask = ntohl (dstEidMask);
    dstPrefLen = LispConvertMaskToPrefLen (dstEidMask);

    printf ("Map-Request received for EID:%s/%d\r\n",
            inet_ntop (AF_INET, &srcEid, buf, sizeof (buf)), srcPrefLen);
    printf ("Sending Map-Reply with EID:%s/%d, ",
            inet_ntop (AF_INET, &dstEid, buf, sizeof (buf)), dstPrefLen);
    printf ("RLOC:%s..\r\n\n", inet_ntop (AF_INET, &rloc, buf, sizeof (buf)));
    return;
}

void DisplayMobileEidMapNotifyLog (uint32_t eid, uint8_t prefLen, 
                                   uint32_t rloc)
{
    char     buf[LISP_MAX_IP_STR_LEN];

    printf ("Mobile EID:%s/%d detected!!\r\n",
            inet_ntop (AF_INET, &eid, buf, sizeof (buf)), prefLen);
    printf ("Informing old ETR RLOC:%s..\r\n\n", 
             inet_ntop (AF_INET, &rloc, buf, sizeof (buf)));
    return;
}
