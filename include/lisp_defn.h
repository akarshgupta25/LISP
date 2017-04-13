/********************************************************************
*
* Filename: lisp_defn.h
*
* Description: This file contains the macros, and function 
*              definitions used in LISP
*
*******************************************************************/

#ifndef __LISP_DEFN_H__
#define __LISP_DEFN_H__

#define LISP_SUCCESS 0
#define LISP_FAILURE 1

#define LISP_TRUE  1
#define LISP_FALSE 0

#define LISP_CMD_LINE_OPT 3
#define LISP_MIN_CMD_LINE_ARG (LISP_CMD_LINE_OPT * 2)
#define LISP_EID_IF_CMD_OPT      "-i"
#define LISP_MSMR_IP_CMD_OPT     "-m"
#define LISP_EID_TO_RLOC_CMD_OPT "-e"
#define LISP_EID_IF_DELIMITER    ","
#define LISP_MAX_EID_IF_NUM      5
#define LISP_MAX_PREF_LEN        32

#define LISP_DATA_PKT_UDP_PORT  4341
#define LISP_CNTRL_PKT_UDP_PORT 4342

#define LISP_MTU_SIZE     1500
#define LISP_IPV4_VERSION 4

#define LISP_HDR_LEN      8
#define LISP_MAC_ADDR_LEN 6
#define LISP_VLAN_TAG_LEN 4
#define LISP_L2_HDR_LEN   14

#define LISP_VLAN_TPID       0x8100
#define LISP_ARP_ETHTYPE     0x0806
#define LISP_IPV4_ETHTYPE    0x0800

#define LISP_DMAC_OFFSET 0
#define LISP_SMAC_OFFSET (LISP_DMAC_OFFSET + LISP_MAC_ADDR_LEN)
#define LISP_ETHTYPE_OFFSET (LISP_SMAC_OFFSET + LISP_MAC_ADDR_LEN)
#define LISP_IP_HDR_OFFSET (LISP_ETHTYPE_OFFSET + 2)

#define LISP_DEF_AUTH_DATA_LEN 4
#define LISP_DEF_RECORD_TLL    0
#define LISP_DEF_MAP_VER_NUM   1

/* Forward declaration */
struct __tEidPrefixRlocMap;
struct __tMobileEidEntry;
struct __tMovedEidEntry;

/* Functions defined in lisp_main.c */
int ValidateCmdLineArg (char *argv[], int argc);
int LispXtrInit (void);
void CleanupLisp (void);

/* Functions defined in lisp_util.c */
int LispOpenEidSockets (void);
int LispOpenDataSockets (void);
int LispOpenControlSockets (void);
int LispConvertPrefixLenToMask (uint8_t prefLen, uint32_t *pMask);
int LispGetIfIpAddr (uint8_t eidIfNum, uint32_t *pIfAddr);
int LispGetEndSysMacAddr (uint32_t ipAddr, uint8_t eidIfNum, uint8_t *pMacAddr);
int LispGetIfMacAddr (uint8_t eidIfNum, uint8_t *pIfMacAddr);
struct __tEidPrefixRlocMap *LispGetEidToRlocMap (uint32_t dstEid);
uint8_t LispConvertMaskToPrefLen (uint32_t mask);
int LispAddRlocEidMapEntry (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                            uint32_t recTtl);
int LispDelRlocEidMapEntry (uint32_t eid, uint8_t prefLen);
int LispAddMobileEidEntry (uint32_t eid, uint8_t prefLen, uint8_t eidIfNum);
struct __tMobileEidEntry *LispGetMobileEidEntry (uint32_t eid, uint8_t eidIfNum);
struct __tMovedEidEntry *LispGetMovedEidEntry (uint32_t eid);
int LispAddMovedEidEntry (uint32_t eid, uint8_t prefLen);

/* Functions defined in lisp_itr.c */
void *ItrTaskMain (void *args);
int LispRecvEndSysPkt (uint8_t eidIfNum);
int LispRecvMapSRPkt (int sockFd);
uint8_t *LispEncapDataPkt (uint8_t *pEndSysData, uint32_t dataLen,
                           uint16_t *pDataPktLen);
int LispSendMapRequest (uint32_t srcEid, uint32_t dstEid);
int LispItrProcessMapRequest (uint8_t *pCntrlPkt, uint16_t cntrlPktLen);

/* Functions defined in lisp_etr.c */
void *EtrTaskMain (void *args);
int LispRecvLispEncpPkt (int sockFd);
int LispRecvLispCntrlPkt (int sockFd);
int LispSendMapRegister (uint32_t srcEid, uint8_t srcEidPrefLen, uint32_t rloc);
int LispSendSolicitMapRequest (uint32_t srcEid, uint32_t dstEid,
                               struct sockaddr_in dstAddr, int dstAddrLen);
int LispSendPktEndSys (uint8_t eidIfNum, uint8_t *pIpv4Pkt, uint16_t ipv4PktLen);
int LispProcessMapNotify (uint8_t *pCntrlPkt, uint16_t cntrlPktLen);

/* Functions defined in lisp_msmr.c */
int LispMSMRInit (void);
void CleanupMSMR (void);
int LispMSMROpenControlSocket (void);
int LispMSMRProcessMapRequest (uint8_t *pCntrlPkt, uint16_t cntrlPktLen,
                               struct sockaddr_in itrAddr, int itrAddrLen);
int LispMSMRProcessMapRegister (uint8_t *pCntrlPkt, uint16_t cntrlPktLen,
                                struct sockaddr_in itrAddr, int itrAddrLen);
struct __tEidPrefixRlocMap *LispMSMRGetEidToRlocMap (uint32_t eid);
int LispMSMRAddRlocEidMapEntry (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                                uint32_t recTtl, uint8_t isProxySet,
                                uint32_t etrAddr);
int LispSendMapReply (uint32_t eid, uint32_t mask, uint32_t rloc, uint32_t ttl,
                      struct sockaddr_in dstAddr, int dstAddrLen);
uint8_t *LispConstructMapReply (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                                uint32_t ttl, uint16_t *pMapRepMsgLen);
int LispSendMapNotify (uint32_t eid, uint8_t prefLen, uint32_t rloc,
                       uint32_t recTtl, uint32_t etrAddr);

/* Debug/Output Functions */
void PrintUsage (void);
void DumpCmdLineArg (void);
void DumpPacket (char *au1Packet, int len);
void DumpSockFd (void);
void DumpLocalMapCache (void);
void DumpMSMRMapDb (void);

#endif /* __LISP_DEFN_H__ */
