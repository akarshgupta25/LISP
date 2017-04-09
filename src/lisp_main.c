/********************************************************************
*
* Filename: lisp_main.c
*
* Description: This file contains LISP xTR initialization code
*
*******************************************************************/

#include "lisp_hdrs.h"

tLispGlobals gLispGlob;

int main (int argc, char *argv[])
{
    void *status = NULL;

    if (ValidateCmdLineArg (argv, argc) != LISP_SUCCESS)
    {
        return LISP_FAILURE;
    }

    if (LispXtrInit() != LISP_SUCCESS)
    {
        CleanupLisp();
        return LISP_FAILURE;
    }

    /* Spawn ITR task */
    if (pthread_create (&gLispGlob.itrTaskId, NULL, (void *) ItrTaskMain, NULL)
        != 0)
    {
        printf ("Failed to create ITR task!!\r\n");
        CleanupLisp();
        return LISP_FAILURE;
    }

    /* Create ETR task */
    if (pthread_create (&gLispGlob.etrTaskId, NULL, (void *) EtrTaskMain, NULL)
        != 0)
    {
        printf ("Failed to create ETR task!!\r\n");
        CleanupLisp();
        return LISP_FAILURE;
    }

    /* NOTE: This should be replaced with some other mechanism
     * such as conditional variable polling */
    pthread_join (gLispGlob.itrTaskId, &status);
    pthread_join (gLispGlob.etrTaskId, &status);

    CleanupLisp();
    return LISP_SUCCESS;
}

int ValidateCmdLineArg (char *argv[], int argc)
{
    uint8_t           index = 1;
    uint8_t           numEidIf = 0;
    uint8_t           numMap = 0;
    uint8_t           prefLen = 0;
    uint32_t          eidMask = 0;
    char              *pEidIf = NULL;
    char              *pEidRlocMap = NULL;
    char              **pEidIfList = NULL;
    tEidPrefixRlocMap *pEidRlocMapList = NULL;

    if (argc < LISP_MIN_CMD_LINE_ARG)
    {
        PrintUsage();
        return LISP_FAILURE;
    }

    memset (&gLispGlob, 0, sizeof (gLispGlob));
    pEidIfList = (char **) &gLispGlob.pEidIfList;
    pEidRlocMapList = (tEidPrefixRlocMap *) &gLispGlob.eidRlocMap;

    while (index < argc)
    {
        /* Get EID interface list */
        if (!strcmp (argv[index], LISP_EID_IF_CMD_OPT))
        {
            index++;
            pEidIf = strtok (argv[index], LISP_EID_IF_DELIMITER);
            if (pEidIf == NULL)
            {
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }

            pEidIfList[numEidIf] = (char *) malloc (strlen (pEidIf) + 1);
            if (pEidIfList[numEidIf] == NULL)
            {
                printf ("Failed to allocate memory!!\r\n");
                CleanupLisp();
                return LISP_FAILURE;
            }
            memset (pEidIfList[numEidIf], 0, strlen (pEidIf) + 1);
            strcpy (pEidIfList[numEidIf], pEidIf);
            numEidIf++;

            while (1)
            {
                pEidIf = strtok (NULL, LISP_EID_IF_DELIMITER);
                /* End of interface list */
                if (pEidIf == NULL)
                {
                    break;
                }

                pEidIfList[numEidIf] = (char *) malloc (strlen (pEidIf) + 1);
                if (pEidIfList[numEidIf] == NULL)
                {
                    printf ("Failed to allocate memory!!\r\n");
                    CleanupLisp();
                    return LISP_FAILURE;
                }
                memset (pEidIfList[numEidIf], 0, strlen (pEidIf) + 1);
                strcpy (pEidIfList[numEidIf], pEidIf);
                numEidIf++;
            }

            gLispGlob.numEidIf = numEidIf;
            index++;
        }

        /* Get Map-Server/Map-Reply IP address */
        if (!strcmp (argv[index], LISP_MSMR_IP_CMD_OPT))
        {
            index++;
            gLispGlob.mapSRIpAddr = inet_addr (argv[index]);
            if (gLispGlob.mapSRIpAddr == INADDR_NONE)
            {
                printf ("Invalid MapSR IP Address!!\r\n");
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }

            index++;
        }

        /* Get EID to RLOC Association */
        if (!strcmp (argv[index], LISP_EID_TO_RLOC_CMD_OPT))
        {
            index++;

            pEidRlocMap = strtok (argv[index], "/");
            if (pEidRlocMap == NULL)
            {
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }
            pEidRlocMapList[numMap].eidPrefix.eid = inet_addr (pEidRlocMap);
            if (pEidRlocMapList[numMap].eidPrefix.eid == INADDR_NONE)
            {
                printf ("Invalid EID!!\r\n");
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }

            pEidRlocMap = strtok (NULL, "/");
            if (pEidRlocMap == NULL)
            {
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }
            prefLen = atoi (pEidRlocMap);
            if (prefLen == 0)
            {
                printf ("Invalid Prefix Length!!\r\n");
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }
            if (LispConvertPrefixLenToMask (prefLen, &eidMask) != LISP_SUCCESS)
            {
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }
            eidMask = htonl (eidMask);
            pEidRlocMapList[numMap].eidPrefix.eid &= eidMask;
            pEidRlocMapList[numMap].eidPrefix.mask = eidMask;

            pEidRlocMap = strtok (pEidRlocMap, ",");
            pEidRlocMap = strtok (NULL, ",");
            if (pEidRlocMap == NULL)
            {
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }
            pEidRlocMapList[numMap].rloc = inet_addr (pEidRlocMap);
            if (pEidRlocMapList[numMap].rloc == INADDR_NONE)
            {
                printf ("Invalid RLOC!!\r\n");
                PrintUsage();
                CleanupLisp();
                return LISP_FAILURE;
            }

            numMap++;
            index++;
        }
    }

    DumpCmdLineArg();

    if (numMap != gLispGlob.numEidIf)
    {
        printf ("Number of EID interfaces and EID Prefixes are unequal!!\r\n");
        CleanupLisp();
        return LISP_FAILURE;
    }

    return LISP_SUCCESS;
}

int LispXtrInit (void)
{
    /* Create raw socket on each EID interface to rx and tx
       end system traffic */
    if (LispOpenEidSockets() != LISP_SUCCESS)
    {
        return LISP_FAILURE;
    }

    /* Create UDP sockets for rx and tx LISP encapsulated packets */
    if (LispOpenDataSockets() != LISP_SUCCESS)
    {
        return LISP_FAILURE;
    }

    /* Create UDP sockets for LISP control messages */
    if (LispOpenControlSockets() != LISP_SUCCESS)
    {
        return LISP_FAILURE;
    }

    /* Initialize ITR Eid Rloc map cache */
    INIT_LIST_HEAD (&gLispGlob.itrEidRlocMapCacheHead);

    /* Initialize ITR map cache lock */
    if (pthread_mutex_init (&gLispGlob.itrMapCacheLock, NULL) < 0)
    {
        printf ("Failed to create ITR map cache mutex!!\r\n");
        return LISP_FAILURE;
    }

    DumpSockFd();

    return LISP_SUCCESS;
}

void CleanupLisp (void)
{
    /* EID If List, sockets, threads */
    return;
}
