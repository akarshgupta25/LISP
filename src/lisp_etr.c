/********************************************************************
*
* Filename: lisp_etr.c
*
* Description: This file contains LISP ETR code
*
*******************************************************************/

#include "lisp_hdrs.h"

extern tLispGlobals gLispGlob;

void *EtrTaskMain (void *args)
{
    int      maxFd = 0;
    int      retVal = 0;
    fd_set   readSet;
    fd_set   tempSet;
    uint32_t mask = 0;
    uint8_t  eidIfNum = 0;
    uint8_t  prefLen = 0;

    FD_ZERO (&readSet);

    /* Calculate maxFd and populate readSet */
    /* Data socket receiving LISP encapsulated packets is part of ETR*/
    FD_SET (gLispGlob.rxLispPktSock, &readSet);
    if (gLispGlob.rxLispPktSock > maxFd)
    {
        maxFd = gLispGlob.rxLispPktSock;
    }
    /* Control socket receiving LISP control messages (Map-notify and SMR)
     * is part of ETR */
    FD_SET (gLispGlob.rxLispCntrlSock, &readSet);
    if (gLispGlob.rxLispCntrlSock > maxFd)
    {
        maxFd = gLispGlob.rxLispCntrlSock;
    }

    /* Send Map-Register message to Map-Server/Resolver for each
     * EID-prefix to RLOC map */
    for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
    {
        mask = ntohl (gLispGlob.eidRlocMap[eidIfNum].eidPrefix.mask);
        prefLen = LispConvertMaskToPrefLen (mask);
        LispSendMapRegister (gLispGlob.eidRlocMap[eidIfNum].eidPrefix.eid, 
                             prefLen,
                             gLispGlob.eidRlocMap[eidIfNum].rloc);
    }

    while (1)
    {
        FD_ZERO (&tempSet);
        memcpy (&tempSet, &readSet, sizeof (tempSet));
        retVal = select (maxFd + 1, &tempSet, NULL, NULL, NULL);
        if (retVal < 0)
        {
            perror ("ETR Select Call");
            break;
        }

        if (FD_ISSET (gLispGlob.rxLispPktSock, &tempSet))
        {
            LispRecvLispEncpPkt (gLispGlob.rxLispPktSock);
        }

        if (FD_ISSET (gLispGlob.rxLispCntrlSock, &tempSet))
        {
            LispRecvLispCntrlPkt (gLispGlob.rxLispCntrlSock);
        }
    }

    pthread_exit (NULL);
}

int LispRecvLispEncpPkt (int sockFd)
{
    struct sockaddr_in itrAddr;
    tEidPrefixRlocMap  *pMapCacheEntry = NULL;
    uint8_t            *pEndSysPkt = NULL;
    int                itrAddrLen = 0;
    uint8_t            lispEncpData[LISP_MTU_SIZE];
    uint8_t            eidIfNum = 0;
    uint8_t            isPktConfigEidMatch = LISP_FALSE;
    uint16_t           endSysPktLen = 0;
    uint16_t           encpPktLen = 0;
    uint32_t           dstEid = 0;
    uint32_t           srcEid = 0;
    uint32_t           srcRloc = 0;

    if (sockFd < 0)
    {
        printf ("Invalid socket descriptor to Rx LISP encap pkt!!\r\n");
        return LISP_FAILURE;
    }

    memset (lispEncpData, 0, sizeof (lispEncpData));
    memset (&itrAddr, 0, sizeof (itrAddr));
    itrAddrLen = sizeof (itrAddr);
    encpPktLen = recvfrom (sockFd, lispEncpData, sizeof (lispEncpData), 0,
                           (struct sockaddr *) &itrAddr,
                           (socklen_t *) &itrAddrLen);
    if (encpPktLen <= 0)
    {
        printf ("Failed to Rx LISP encapsulated pkt!!\r\n");
        return LISP_FAILURE;
    }

    pEndSysPkt = lispEncpData + LISP_HDR_LEN;
    endSysPktLen = encpPktLen - LISP_HDR_LEN;

    /* NOTE: Maybe this needs to be changed */
    /* Only process LISP encapsulated IP packets */
    if (((tIpv4Hdr *) pEndSysPkt)->version != LISP_IPV4_VERSION)
    {
        printf ("LISP encapsulated pkt is not IP!!\r\n");
        return LISP_FAILURE;
    }

    DumpPacket ((char *) pEndSysPkt, endSysPktLen);

    /* Check destination EID of packet:
     * 1) If matches interface EID, then check if destination EID belongs to
     *    invalid/moved EID list. If present in moved EID list then send
     *    SMR message to ITR. Otherwise forward packet.   
     * 2) If does not match interface EID, then check if dest EID belongs to
     *    list of registered mobile EIDs. If present then forward packet,
     *    otherwise drop packet */

    dstEid = ((tIpv4Hdr *) pEndSysPkt)->dstIpAddr;
    srcEid = ((tIpv4Hdr *) pEndSysPkt)->srcIpAddr;
    srcRloc = itrAddr.sin_addr.s_addr;

    for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
    {
        if ((dstEid & gLispGlob.eidRlocMap[eidIfNum].eidPrefix.mask) ==
             gLispGlob.eidRlocMap[eidIfNum].eidPrefix.eid)
        {
            /* Packet destination to configured EID-prefix */
            isPktConfigEidMatch = LISP_TRUE;
            break;
        }
    }

    switch (isPktConfigEidMatch)
    {
        case LISP_TRUE:
            if (LispGetMovedEidEntry (dstEid) != NULL)
            {
                /* Send SMR message to ITR */
                LispSendSolicitMapRequest (srcEid, dstEid, itrAddr, 
                                           itrAddrLen);
                return LISP_SUCCESS;
            }

            /* Update source EID to RLOC mapping in local cache */
            pMapCacheEntry = LispGetEidToRlocMap (srcEid);
            if (pMapCacheEntry == NULL)
            {
                LispAddRlocEidMapEntry (srcEid, LISP_MAX_PREF_LEN, srcRloc);
            }   
            else if (pMapCacheEntry->rloc != srcRloc)
            {
                pthread_mutex_lock (&gLispGlob.itrMapCacheLock);
                pMapCacheEntry->rloc = srcRloc;
                pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);
            }

            DumpLocalMapCache();

            /* Forward packet to appropriate end system EID */
            LispSendPktEndSys (eidIfNum, pEndSysPkt, endSysPktLen);
            break;

        case LISP_FALSE:
            if (LispGetMobileEidEntry (dstEid) == NULL)
            {
                return LISP_SUCCESS;
            }

            /* Update source EID to RLOC mapping in local cache */
            pMapCacheEntry = LispGetEidToRlocMap (srcEid);
            if (pMapCacheEntry == NULL)
            {
                LispAddRlocEidMapEntry (srcEid, LISP_MAX_PREF_LEN, srcRloc);
            }
            else if (pMapCacheEntry->rloc != srcRloc)
            {
                pthread_mutex_lock (&gLispGlob.itrMapCacheLock);
                pMapCacheEntry->rloc = srcRloc;
                pthread_mutex_unlock (&gLispGlob.itrMapCacheLock);
            }

            DumpLocalMapCache();

            /* Forward packet to appropriate end system EID */
            LispSendPktEndSys (eidIfNum, pEndSysPkt, endSysPktLen);
            break;

        default:
            return LISP_FAILURE;
    }

    return LISP_SUCCESS;
}

int LispRecvLispCntrlPkt (int sockFd)
{
    struct sockaddr_in  srcAddr;
    int                 srcAddrLen = 0;
    uint8_t             cntrlPkt[LISP_MTU_SIZE];
    uint16_t            cntrlPktLen = 0;
    uint8_t             lispMsgType = 0;

    memset (cntrlPkt, 0, sizeof (cntrlPkt));
    memset (&srcAddr, 0, sizeof (srcAddr));
    srcAddrLen = sizeof (srcAddr);
    cntrlPktLen = recvfrom (sockFd, cntrlPkt, sizeof (cntrlPkt), 0,
                            (struct sockaddr *) &srcAddr,
                            (socklen_t *) &srcAddrLen);
    if (cntrlPktLen <= 0)
    {
        printf ("Failed to Rx LISP control packet!!\r\n");
        return LISP_FAILURE;
    }

    lispMsgType = ((cntrlPkt[0] >> 4) & 0xF);
    switch (lispMsgType)
    {
        case LISP_MAP_REQ_MSG:
            LispItrProcessMapRequest (cntrlPkt, cntrlPktLen);
            break;

        case LISP_MAP_NOTIFY_MSG:
            break;

        default:
            return LISP_FAILURE;
    }

    return LISP_SUCCESS;
}

int LispSendMapRegister (uint32_t eid, uint8_t eidPrefLen, uint32_t rloc)
{
    tMapRegHdr         *pMapRegMsg = NULL;
    tRlocRecord        *pRlocRec = NULL;
    tRlocLoc           *pLoc = NULL;
    struct sockaddr_in mapSRAddr;
    uint16_t           mapRegMsgLen = 0;

    mapRegMsgLen = sizeof (tRlocLoc) + sizeof (tRlocRecord) + 
                   sizeof (tMapRegHdr);
    pMapRegMsg = (tMapRegHdr *) malloc (mapRegMsgLen);
    if (pMapRegMsg == NULL)
    {
        printf ("Failed to allocate memory to Map-Register message!!\r\n");
        return LISP_FAILURE;
    }
    memset (pMapRegMsg, 0, mapRegMsgLen);

    pMapRegMsg->type = LISP_MAP_REG_MSG;

    /* Enable proxy Map-Reply */
    pMapRegMsg->proxyBit = 1;
    pMapRegMsg->recordCount = 1;
    pMapRegMsg->authDataLen = htons (LISP_DEF_AUTH_DATA_LEN);

    pRlocRec = (tRlocRecord *) 
               (((uint8_t *) pMapRegMsg) + sizeof (tMapRegHdr));

    pRlocRec->recTtl = htonl (LISP_DEF_RECORD_TLL);
    pRlocRec->locCount = 1;
    pRlocRec->eidPrefLen = eidPrefLen;
    pRlocRec->eidPrefixAfi = htons (LISP_IPV4_AFI);
    pRlocRec->eidPrefix = eid;

    pLoc = (tRlocLoc *)
           (((uint8_t *) pRlocRec) + sizeof (tRlocRecord));

    pLoc->rlocAfi = htons (LISP_IPV4_AFI);
    pLoc->rloc = rloc;

    /* Send Map-Register to Map-Server/Map-Resolver */
    memset (&mapSRAddr, 0, sizeof (mapSRAddr));
    mapSRAddr.sin_family = AF_INET;
    mapSRAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    mapSRAddr.sin_addr.s_addr = gLispGlob.mapSRIpAddr;
    sendto (gLispGlob.txLispCntrlSock, pMapRegMsg, mapRegMsgLen, 0,
            (struct sockaddr *) &mapSRAddr, sizeof (mapSRAddr));

    free (pMapRegMsg);
    pMapRegMsg = NULL;

    return LISP_SUCCESS;
}

int LispSendSolicitMapRequest (uint32_t srcEid, uint32_t dstEid, 
                               struct sockaddr_in dstAddr, int dstAddrLen)
{
    uint8_t        *pSMReqMsg = NULL;
    tMapReqFlags   flags;
    uint32_t       itrRloc = 0;
    uint16_t       smReqMsgLen = 0;

    memset (&flags, 0, sizeof (flags));
    flags.smrBit = 1;
    itrRloc = dstAddr.sin_addr.s_addr;
    pSMReqMsg = LispConstructMapRequest (srcEid, itrRloc, dstEid,
                                         LISP_MAX_PREF_LEN, flags,
                                         &smReqMsgLen);
    if (pSMReqMsg == NULL)
    {
        printf ("Failed to contruct SMR Message!!\r\n");
        return LISP_FAILURE;
    }

     /* Send Solict Map-Request to ITR */
    dstAddr.sin_family = AF_INET;
    dstAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    sendto (gLispGlob.txLispCntrlSock, pSMReqMsg, smReqMsgLen, 0,
            (struct sockaddr *) &dstAddr, dstAddrLen);

    free (pSMReqMsg);
    pSMReqMsg = NULL;
    return LISP_SUCCESS;
}

int LispSendPktEndSys (uint8_t eidIfNum, uint8_t *pIpv4Pkt, uint16_t ipv4PktLen)
{
    uint8_t    ifMacAddr[LISP_MAC_ADDR_LEN];
    uint8_t    endSysMacAddr[LISP_MAC_ADDR_LEN];
    uint8_t    *pEndSysPkt = NULL;
    uint16_t   endSysPktLen = 0;
    uint16_t   ethType = 0;

    endSysPktLen = ipv4PktLen + LISP_L2_HDR_LEN;
    pEndSysPkt = (uint8_t *) malloc (endSysPktLen);
    if (pEndSysPkt == NULL)
    {
        printf ("Failed to allocate memory to Tx end system pkt!!\r\n");
        return LISP_FAILURE;
    }
    memset (pEndSysPkt, 0, sizeof (endSysPktLen));

    memset (endSysMacAddr, 0, sizeof (endSysMacAddr));
    if (LispGetEndSysMacAddr (((tIpv4Hdr *) pIpv4Pkt)->dstIpAddr, eidIfNum,
                              endSysMacAddr) != LISP_SUCCESS)
    {
        printf ("Failed to fetch end system MAC address!!\r\n");
        return LISP_FAILURE;
    }

    memset (ifMacAddr, 0, sizeof (ifMacAddr));
    if (LispGetIfMacAddr (eidIfNum, ifMacAddr) != LISP_SUCCESS)
    {
        printf ("Failed to fetch interface MAC address!!\r\n");
        return LISP_FAILURE;
    }

    memcpy (pEndSysPkt, endSysMacAddr, LISP_MAC_ADDR_LEN);
    memcpy (pEndSysPkt + LISP_SMAC_OFFSET, ifMacAddr, LISP_MAC_ADDR_LEN);
    ethType = htons (LISP_IPV4_ETHTYPE);
    memcpy (pEndSysPkt + LISP_ETHTYPE_OFFSET, &ethType, sizeof (ethType)); 
    memcpy (pEndSysPkt + LISP_IP_HDR_OFFSET, pIpv4Pkt, ipv4PktLen);

    send (gLispGlob.rawSockFd[eidIfNum], pEndSysPkt, endSysPktLen, 0);

    free (pEndSysPkt);
    pEndSysPkt = NULL;
    return LISP_SUCCESS;
}
