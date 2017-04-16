/********************************************************************
*
* Filename: lisp_itr.c
*
* Description: This file contains LISP ITR code
*
*******************************************************************/

#include "lisp_hdrs.h"

extern tLispGlobals gLispGlob;

void *ItrTaskMain (void *args)
{
    int      maxFd = 0;
    int      retVal = 0;
    uint8_t  eidIfNum = 0;
    fd_set   readSet;
    fd_set   tempSet;

    FD_ZERO (&readSet);

    /* Calculate maxFd and populate readSet */
    for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
    {
        /* Raw sockets receiving traffic from end systems are part of ITR */
        FD_SET (gLispGlob.rawSockFd[eidIfNum], &readSet);
        if (gLispGlob.rawSockFd[eidIfNum] > maxFd)
        {
            maxFd = gLispGlob.rawSockFd[eidIfNum];
        }
    }
    /* Control socket communicating with MS/MR is part of ITR */
    FD_SET (gLispGlob.txLispCntrlSock, &readSet);
    if (gLispGlob.txLispCntrlSock > maxFd)
    {
        maxFd = gLispGlob.txLispCntrlSock;
    }

    while (1)
    {
        FD_ZERO (&tempSet);
        memcpy (&tempSet, &readSet, sizeof (tempSet));
        /* Wait for read event on sockets */
        retVal = select (maxFd + 1, &tempSet, NULL, NULL, NULL);
        if (retVal < 0)
        {
            perror ("ITR Select Call");
            break;
        }

        for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
        {
            if (FD_ISSET (gLispGlob.rawSockFd[eidIfNum], &tempSet))
            {
                LispRecvEndSysPkt (eidIfNum);
            }
        }

        if (FD_ISSET (gLispGlob.txLispCntrlSock, &tempSet))
        {
            LispRecvMapSRPkt (gLispGlob.txLispCntrlSock);
        }
    }

    pthread_exit (NULL);
}

int LispRecvEndSysPkt (uint8_t eidIfNum)
{
    struct sockaddr_ll recvAddr;
    struct sockaddr_in etrAddr;
    tIpv4Hdr           *pIpv4Pkt = NULL;
    tArpHdr            *pArpHdr = NULL;
    tEidPrefixRlocMap  *pEidRlocMapEntry = NULL;
    uint8_t            *pLispEncpDataPkt = NULL;
    uint8_t            srcMacAddr[LISP_MAC_ADDR_LEN];
    int                sockFd = 0;
    int                recvAddrLen = 0;
    uint8_t            endSysData[LISP_MTU_SIZE];
    uint16_t           dataLen = 0;
    uint16_t           l3HdrOffset = 0;
    uint16_t           encpPktLen = 0;
    uint16_t           ethType = 0;
    uint32_t           dstEid = 0;
    uint32_t           srcEid = 0;
    uint32_t           ifIpAddr = 0;

    if (eidIfNum >= gLispGlob.numEidIf)
    {
        printf ("Invalid EID interface to Rx end system pkt!!\r\n");
        return LISP_FAILURE;
    }
    sockFd = gLispGlob.rawSockFd[eidIfNum];

    memset (endSysData, 0, sizeof (endSysData));
    memset (&recvAddr, 0, sizeof (recvAddr));
    dataLen = recvfrom (sockFd, endSysData, sizeof (endSysData), 0,
                        (struct sockaddr *) &recvAddr, 
                        (socklen_t *) &recvAddrLen);
    if (dataLen <= 0)
    {
        printf ("Failed to Rx end system pkt!!\r\n");
        return LISP_FAILURE;
    }

    if (LispGetIfIpAddr (eidIfNum, &ifIpAddr) != LISP_SUCCESS)
    {
        printf ("Could not fetch EID interface IP address!!\r\n");
        return LISP_FAILURE;
    }

    memset (srcMacAddr, 0, sizeof (srcMacAddr));
    memcpy (srcMacAddr, endSysData + LISP_SMAC_OFFSET, LISP_MAC_ADDR_LEN);

    l3HdrOffset += (2 * LISP_MAC_ADDR_LEN);
    ethType = htons (LISP_VLAN_TPID);
    if (!memcmp (endSysData + l3HdrOffset, &ethType, sizeof (ethType)))
    {
        l3HdrOffset += LISP_VLAN_TAG_LEN;
    }

    ethType = htons (LISP_ARP_ETHTYPE);
    if (!memcmp (endSysData + l3HdrOffset, &ethType, sizeof (ethType)))
    {
        pArpHdr = (tArpHdr *) (endSysData + l3HdrOffset + sizeof (ethType));
        LispItrProcessEndSysArpPkt (pArpHdr, eidIfNum, srcMacAddr);

#if 0
        printf ("Pkt received from end system is not IP!!\r\n");
#endif
        return LISP_SUCCESS;
    }

    /* Only process IP packets */
    ethType = htons (LISP_IPV4_ETHTYPE);
    if (memcmp (endSysData + l3HdrOffset, &ethType, sizeof (ethType)))
    {
#if 0
        printf ("Pkt Rx on raw socket is not IP!!\r\n");
#endif
        return LISP_SUCCESS;
    }
    l3HdrOffset += sizeof (ethType);

    pIpv4Pkt = (tIpv4Hdr *) (endSysData + l3HdrOffset);
    dstEid = pIpv4Pkt->dstIpAddr;
    srcEid = pIpv4Pkt->srcIpAddr;

    /* Do not process local host transmitted packets */
    if (srcEid == ifIpAddr)
    {
        printf ("Local host Tx packet, do not process!!\r\n");
        return LISP_SUCCESS;
    }

    LispItrUpdateEndSysArpEntry (srcEid, srcMacAddr);

    /* If source EID is different from ETR EID-prefix then it is 
     * received from a mobile device */
    if ((srcEid & gLispGlob.eidRlocMap[eidIfNum].eidPrefix.mask) !=
         gLispGlob.eidRlocMap[eidIfNum].eidPrefix.eid)
    {
        /* Check if srcEid is present in list of registered mobile devices:
         * 1) If present then continue processing the packet
         * 2) Otherwise send map register message and add device in list of
         *    registered mobile devices */
        if (LispGetMobileEidEntry (srcEid, eidIfNum) == NULL)
        {
            DisplayItrMobileEidDiscLog (srcEid);
            LispSendMapRegister (srcEid, LISP_MAX_PREF_LEN,
                                 gLispGlob.eidRlocMap[eidIfNum].rloc);
            LispAddMobileEidEntry (srcEid, LISP_MAX_PREF_LEN, eidIfNum,
                                   srcMacAddr);
            LispDelMovedEidEntry (srcEid, LISP_MAX_PREF_LEN);
            DumpMovedEidList();
            DumpMobileEidList();
        }
    }
    else
    {
        /* Packet received from end system in the same EID-prefix:
         * If srcEid is present in moved Eid list, then a moved Eid
         * has returned to LISP site. Send Map-Register */
        if (LispGetMovedEidEntry (srcEid) != NULL)
        {
            DisplayItrMovedEidReturnLog (srcEid);
            LispSendMapRegister (srcEid, LISP_MAX_PREF_LEN,
                                 gLispGlob.eidRlocMap[eidIfNum].rloc);
            LispDelMovedEidEntry (srcEid, LISP_MAX_PREF_LEN);
            DumpMovedEidList();
            DumpMobileEidList();
        }
    }

    /* Do not further process local host destined packets */
    if (dstEid == ifIpAddr)
    {
        printf ("Local host Rx packet, do not process!!\r\n");
        return LISP_SUCCESS;
    }

    DumpItrRxEndSysPkt (srcEid, dstEid);

    /* Search destination EID to RLOC mapping in local cache */
    pEidRlocMapEntry = LispGetEidToRlocMap (dstEid);
    if (pEidRlocMapEntry == NULL)
    {
        /* Entry does not exist, send Map-Request */
        DisplayItrMapCacheMissLog (dstEid);
        LispSendMapRequest (srcEid, dstEid);
        return LISP_SUCCESS;
    }

    /* Drop packet if RLOC is not present in mapping */    
    if (pEidRlocMapEntry->rloc == 0)
    {
        DisplayItrNegMapLog (dstEid);
        return LISP_SUCCESS;
    }

    /* Entry exists, encapsulate packet and forward to appropriate
     * ETR RLOC */
    pLispEncpDataPkt = LispEncapDataPkt ((uint8_t *) pIpv4Pkt, 
                                         dataLen - l3HdrOffset, 
                                         &encpPktLen);
    if (pLispEncpDataPkt == NULL)
    {
        printf ("Failed to encapsulate data packet!!\r\n");
        return LISP_FAILURE;
    }

    DisplayItrTxLispEncpPktLog (pEidRlocMapEntry->rloc);

    memset (&etrAddr, 0, sizeof (etrAddr));
    etrAddr.sin_family = AF_INET;
    etrAddr.sin_port = htons (LISP_DATA_PKT_UDP_PORT);
    etrAddr.sin_addr.s_addr = pEidRlocMapEntry->rloc;
    sendto (gLispGlob.txLispPktSock, pLispEncpDataPkt, encpPktLen, 0,
            (struct sockaddr *) &etrAddr, sizeof (etrAddr));

    free (pLispEncpDataPkt);
    pLispEncpDataPkt = NULL;

    return LISP_SUCCESS;
}

int LispRecvMapSRPkt (int sockFd)
{
    struct sockaddr_in  mapSRAddr;
    tMapRepHdr          *pMapRepMsg = NULL;
    tRlocRecord         *pRlocRec = NULL;
    tRlocLoc            *pLoc = NULL;
    uint8_t             mapSRData[LISP_MTU_SIZE];
    int                 mapSRAddrLen = 0;
    uint16_t            mapSRDataLen = 0;
    uint32_t            eid = 0;
    uint32_t            mask = 0;

    memset (mapSRData, 0, sizeof (mapSRData));
    memset (&mapSRAddr, 0, sizeof (mapSRAddr));
    mapSRAddrLen = sizeof (mapSRAddr);
    mapSRDataLen = recvfrom (sockFd, mapSRData, sizeof (mapSRData), 0,
                             (struct sockaddr *) &mapSRAddr, 
                             (socklen_t *) &mapSRAddrLen);
    if (mapSRDataLen <= 0)
    {
        printf ("Failed to Rx message from Map-Server/Map-Resolver!!\r\n");
        return LISP_FAILURE;
    }

    pMapRepMsg = (tMapRepHdr *) mapSRData;
    /* Only process Map-Reply from Map-Server/Map-Resolver */
    if (pMapRepMsg->type != LISP_MAP_REP_MSG)
    {
        printf ("Message Rx from Map-Server/Map-Resolver " 
                "is not Map-Reply!!\r\n");
        return LISP_FAILURE;
    }

    if (pMapRepMsg->recordCount == 0)
    {
        printf ("Map-Reply does not consist of Records!!\r\n");
        return LISP_FAILURE;
    }

    pRlocRec = (tRlocRecord *)
               (((uint8_t *) pMapRepMsg) + sizeof (tMapRepHdr));
    if (pRlocRec->locCount == 0)
    {
        /* NOTE: Negative Map-Reply received */
        return LISP_SUCCESS;
    }

    if (LispConvertPrefixLenToMask (pRlocRec->eidPrefLen, &mask)
        != LISP_SUCCESS)
    {
        printf ("Invalid EID-prefix mask received in Map-Reply message!!\r\n");
        return LISP_FAILURE;
    }
    mask = htonl (mask);
    eid = pRlocRec->eidPrefix & mask;
    
    pLoc = (tRlocLoc *)
           (((uint8_t *) pRlocRec) + sizeof (tRlocRecord));

    DisplayItrAddMapCacheLog (eid, pRlocRec->eidPrefLen, pLoc->rloc);

    LispAddRlocEidMapEntry (eid, pRlocRec->eidPrefLen, pLoc->rloc, 
                            pRlocRec->recTtl);

    return LISP_SUCCESS;
}

int LispSendMapRequest (uint32_t srcEid, uint32_t dstEid)
{
    uint8_t            *pMapReqMsg = NULL;
    struct sockaddr_in mapSRAddr;
    tMapReqFlags       flags;
    uint32_t           itrRloc = 0;
    uint16_t           mapReqMsgLen = 0;
    uint8_t            eidIfNum = 0;
    uint8_t            isEidMatch = LISP_FALSE;

    /* Determine ITR Rloc from local EID-prefix to RLOC map */
    for (eidIfNum = 0; eidIfNum < gLispGlob.numEidIf; eidIfNum++)
    {
        if ((srcEid & gLispGlob.eidRlocMap[eidIfNum].eidPrefix.mask) ==
             gLispGlob.eidRlocMap[eidIfNum].eidPrefix.eid)
        {
            isEidMatch = LISP_TRUE;
            break;
        }
    }
    itrRloc = (isEidMatch == LISP_TRUE) ?
              gLispGlob.eidRlocMap[eidIfNum].rloc : 
              gLispGlob.eidRlocMap[0].rloc; /* default RLOC */

    memset (&flags, 0, sizeof (flags));
    pMapReqMsg = LispConstructMapRequest (srcEid, itrRloc, dstEid, 
                                          LISP_MAX_PREF_LEN, flags,
                                          &mapReqMsgLen);
    if (pMapReqMsg == NULL)
    {
        printf ("Failed to construct Map Request message!!\r\n");
        return LISP_FAILURE;
    }

    /* Send Map-Request to Map-Server/Map-Resolver */
    memset (&mapSRAddr, 0, sizeof (mapSRAddr));
    mapSRAddr.sin_family = AF_INET;
    mapSRAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    mapSRAddr.sin_addr.s_addr = gLispGlob.mapSRIpAddr;
    sendto (gLispGlob.txLispCntrlSock, pMapReqMsg, mapReqMsgLen, 0,
            (struct sockaddr *) &mapSRAddr, sizeof (mapSRAddr));

    free (pMapReqMsg);
    pMapReqMsg = NULL;
    return LISP_SUCCESS;
}

uint8_t *LispEncapDataPkt (uint8_t *pEndSysData, uint32_t dataLen,
                           uint16_t *pDataPktLen)
{
    uint8_t   *pDataPkt = NULL;
    uint16_t   dataPktLen = 0;

    if ((pEndSysData == NULL) || (pDataPktLen == NULL))
    {
        return NULL;
    }

    dataPktLen = dataLen + LISP_HDR_LEN;
    pDataPkt = (uint8_t *) malloc (dataPktLen);
    if (pDataPkt == NULL)
    {
        printf ("Failed to allocate memory to LISP Encap data packet!!\r\n");
        return NULL;
    }
    memset (pDataPkt, 0, dataPktLen);

    /* Set LISP header values */
    /* Nothing set in LISP header presently */

    /* Copy original IP packet */
    memcpy (pDataPkt + LISP_HDR_LEN, pEndSysData, dataLen);

    *pDataPktLen = dataPktLen;
    return pDataPkt;
}

int LispItrProcessMapRequest (uint8_t *pCntrlPkt, uint16_t cntrlPktLen)
{
    tMapReqHdr         *pSMReqMsg = NULL;
    tMapReqRec         *pMapReqRec = NULL;
    tMapReqFlags       flags;
    struct sockaddr_in mapSRAddr;
    uint8_t            *pMapReqMsg = NULL;
    uint32_t           srcEid = 0;
    uint32_t           itrRloc = 0;
    uint16_t           mapReqMsgLen = 0;

    if (pCntrlPkt == NULL)
    {
        printf ("[%s]: Invalid parameter!!\r\n", __func__);
        return LISP_FAILURE;
    }

    pSMReqMsg = (tMapReqHdr *) pCntrlPkt;

    /* Only process Solicit Map Request */
    if (pSMReqMsg->smrBit != 1)
    {
        return LISP_SUCCESS;
    }
    if (pSMReqMsg->recordCount == 0)
    {
        printf ("SMR message does not contain Records!!\r\n");
        return LISP_FAILURE;
    }

    pMapReqRec = (tMapReqRec *)
                 (((uint8_t *) pSMReqMsg) + sizeof (tMapReqHdr));

    memset (&flags, 0, sizeof (flags));
    flags.smrInvokBit = 1;

    srcEid = ((ntohs (pSMReqMsg->srcEidHi) << 16) & 0xFFFF0000) | 
              (ntohs (pSMReqMsg->srcEidLo));
    srcEid = htonl (srcEid);

    itrRloc = ((ntohs (pSMReqMsg->itrRlocHi) << 16) & 0xFFFF0000) |
               (ntohs (pSMReqMsg->itrRlocLo));
    itrRloc = htonl (itrRloc);

    /* Delete present entry in local map cache for this destination 
     * EID-prefix */
    LispDelRlocEidMapEntry (pMapReqRec->dstEid, pMapReqRec->dstEidPrefLen);

    pMapReqMsg = LispConstructMapRequest (srcEid, itrRloc, pMapReqRec->dstEid,
                                          pMapReqRec->dstEidPrefLen, flags,
                                          &mapReqMsgLen);
    if (pMapReqMsg == NULL)
    {
        printf ("Failed to contruct Map Request message!!\r\n");
        return LISP_FAILURE;
    }

    DisplayItrSMReqLog (pMapReqRec->dstEid);

    memset (&mapSRAddr, 0, sizeof (mapSRAddr));
    mapSRAddr.sin_family = AF_INET;
    mapSRAddr.sin_port = htons (LISP_CNTRL_PKT_UDP_PORT);
    mapSRAddr.sin_addr.s_addr = gLispGlob.mapSRIpAddr;
    sendto (gLispGlob.txLispCntrlSock, pMapReqMsg, mapReqMsgLen, 0,
            (struct sockaddr *) &mapSRAddr, sizeof (mapSRAddr));

    free (pMapReqMsg);
    pMapReqMsg = NULL;
    return LISP_SUCCESS;
}

int LispItrProcessEndSysArpPkt (tArpHdr *pArpHdr, uint8_t eidIfNum,
                                uint8_t *pSrcMacAddr)
{
    uint32_t    srcEid = 0;
    uint32_t    dstEid = 0;
    uint32_t    ifIpAddr = 0;

    if ((pArpHdr == NULL) || (pSrcMacAddr == NULL))
    {
        printf ("[%s]: Invalid Parameter!!\r\n", __func__);
        return LISP_FAILURE;
    }

    if (LispGetIfIpAddr (eidIfNum, &ifIpAddr) != LISP_SUCCESS)
    {
        printf ("Could not fetch EID interface IP address!!\r\n");
        return LISP_FAILURE;
    }

    memcpy (&srcEid, pArpHdr->srcIpAddr, sizeof (srcEid));
    memcpy (&dstEid, pArpHdr->dstIpAddr, sizeof (dstEid));

    if (srcEid == ifIpAddr)
    {
        return LISP_SUCCESS;
    }

    LispItrUpdateEndSysArpEntry (srcEid, pSrcMacAddr);

    /* If ARP is received from mobile device then add to mobile device
     * list */
    if ((srcEid & gLispGlob.eidRlocMap[eidIfNum].eidPrefix.mask) !=
        gLispGlob.eidRlocMap[eidIfNum].eidPrefix.eid)
    {
        if (LispGetMobileEidEntry (srcEid, eidIfNum) == NULL)
        {
            DisplayItrMobileEidDiscLog (srcEid);
            LispSendMapRegister (srcEid, LISP_MAX_PREF_LEN,
                                 gLispGlob.eidRlocMap[eidIfNum].rloc);
            LispAddMobileEidEntry (srcEid, LISP_MAX_PREF_LEN, eidIfNum,
                                   pSrcMacAddr);
            LispDelMovedEidEntry (srcEid, LISP_MAX_PREF_LEN);
            DumpMovedEidList();
            DumpMobileEidList();
        }
    }
    else
    {
        /* ARP received from end system in the same EID-prefix:
         * If srcEid is present in moved Eid list, then a moved Eid
         * has returned to LISP site. Send Map-Register */
        if (LispGetMovedEidEntry (srcEid) != NULL)
        {
            DisplayItrMovedEidReturnLog (srcEid);
            LispSendMapRegister (srcEid, LISP_MAX_PREF_LEN,
                                 gLispGlob.eidRlocMap[eidIfNum].rloc);
            LispDelMovedEidEntry (srcEid, LISP_MAX_PREF_LEN);
            DumpMovedEidList();
            DumpMobileEidList();
        }
    }

    return LISP_SUCCESS;
}
