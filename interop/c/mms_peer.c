/*
 * mms_peer: drives libiec61850's client through the MMS services the
 * interop suite checks against the Go server.
 *
 *   mms_peer HOST PORT [-p PASSWORD] COMMAND...
 *
 * COMMAND is one of
 *   status              MMS Status                  -> "status logical=L physical=P err=E"
 *   setfile LOCAL NAME  IEC 61850 SetFile (obtainFile) -> "setfile err=E"
 *   deletefile NAME     IEC 61850 DeleteFile        -> "deletefile err=E"
 *   rename OLD NEW      MMS fileRename              -> "rename err=E" (an MmsError)
 *   dir                 file directory              -> "file NAME SIZE" per file
 *   release             release (MMS conclude)      -> "release err=E"
 *   abort               abort                       -> "abort err=E"
 *   svcb REF            SV control block state      -> "svcb REF multicast=M svena=S resv=R id=ID err=E"
 *   svena REF 0|1       write SvEna                 -> "svena err=E"
 *   svresv REF 0|1      write Resv (FC US)          -> "svresv err=E"
 *
 * svcb and svena go through ClientSVControlBlock, which tells an MSVCB
 * from a USVCB by reading the block under FC MS, then US. svresv writes
 * Resv directly: ClientSVControlBlock_setResv writes SvEna instead.
 *
 * The connection result is printed first, "connect err=E". E is the
 * IedClientError (0 is success). The peer exits 0 when every step it ran
 * reported 0, 1 otherwise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iec61850_client.h"
#include "mms_client_connection.h"

int
main(int argc, char** argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s HOST PORT [-p PASSWORD] COMMAND...\n", argv[0]);
        return 2;
    }
    const char* host = argv[1];
    int port = atoi(argv[2]);
    int i = 3;

    IedConnection con = IedConnection_create();
    IedClientError err;
    int failed = 0;

    if (i + 1 < argc && strcmp(argv[i], "-p") == 0) {
        MmsConnection mms = IedConnection_getMmsConnection(con);
        IsoConnectionParameters params = MmsConnection_getIsoConnectionParameters(mms);
        AcseAuthenticationParameter auth = AcseAuthenticationParameter_create();
        AcseAuthenticationParameter_setAuthMechanism(auth, ACSE_AUTH_PASSWORD);
        AcseAuthenticationParameter_setPassword(auth, argv[i + 1]);
        IsoConnectionParameters_setAcseAuthenticationParameter(params, auth);
        i += 2;
    }

    IedConnection_connect(con, &err, host, port);
    printf("connect err=%d\n", err);
    fflush(stdout);
    if (err != IED_ERROR_OK) {
        IedConnection_destroy(con);
        return 1;
    }

    for (; i < argc; i++) {
        const char* cmd = argv[i];
        if (strcmp(cmd, "status") == 0) {
            MmsError merr;
            int logical = -1, physical = -1;
            MmsConnection_getServerStatus(IedConnection_getMmsConnection(con), &merr, &logical, &physical, false);
            printf("status logical=%d physical=%d err=%d\n", logical, physical, merr);
            failed |= merr != MMS_ERROR_NONE;
        }
        else if (strcmp(cmd, "setfile") == 0 && i + 2 < argc) {
            IedConnection_setFile(con, &err, argv[i + 1], argv[i + 2]);
            printf("setfile err=%d\n", err);
            failed |= err != IED_ERROR_OK;
            i += 2;
        }
        else if (strcmp(cmd, "deletefile") == 0 && i + 1 < argc) {
            IedConnection_deleteFile(con, &err, argv[i + 1]);
            printf("deletefile err=%d\n", err);
            failed |= err != IED_ERROR_OK;
            i += 1;
        }
        else if (strcmp(cmd, "rename") == 0 && i + 2 < argc) {
            MmsError merr;
            MmsConnection_fileRename(IedConnection_getMmsConnection(con), &merr, argv[i + 1], argv[i + 2]);
            printf("rename err=%d\n", merr);
            failed |= merr != MMS_ERROR_NONE;
            i += 2;
        }
        else if (strcmp(cmd, "dir") == 0) {
            LinkedList files = IedConnection_getFileDirectory(con, &err, NULL);
            if (files) {
                LinkedList e = LinkedList_getNext(files);
                while (e) {
                    FileDirectoryEntry f = (FileDirectoryEntry) LinkedList_getData(e);
                    printf("file %s %u\n", FileDirectoryEntry_getFileName(f), FileDirectoryEntry_getFileSize(f));
                    e = LinkedList_getNext(e);
                }
                LinkedList_destroyDeep(files, (LinkedListValueDeleteFunction) FileDirectoryEntry_destroy);
            }
            printf("dir err=%d\n", err);
            failed |= err != IED_ERROR_OK;
        }
        else if (strcmp(cmd, "release") == 0) {
            IedConnection_release(con, &err);
            printf("release err=%d\n", err);
            failed |= err != IED_ERROR_OK;
        }
        else if (strcmp(cmd, "abort") == 0) {
            IedConnection_abort(con, &err);
            printf("abort err=%d\n", err);
            failed |= err != IED_ERROR_OK;
        }
        else if (strcmp(cmd, "svcb") == 0 && i + 1 < argc) {
            ClientSVControlBlock cb = ClientSVControlBlock_create(con, argv[i + 1]);
            if (cb == NULL) {
                printf("svcb %s err=-1\n", argv[i + 1]);
                failed = 1;
            }
            else {
                bool mc = ClientSVControlBlock_isMulticast(cb);
                IedClientError e = IED_ERROR_OK;
                bool ena = ClientSVControlBlock_getSvEna(cb);
                e = e ? e : ClientSVControlBlock_getLastComError(cb);
                bool resv = false;
                char* id;
                if (mc) {
                    id = ClientSVControlBlock_getMsvID(cb);
                    e = e ? e : ClientSVControlBlock_getLastComError(cb);
                }
                else {
                    /* ClientSVControlBlock_getMsvID reads MsvID, which a USVCB calls UsvID. */
                    char ref[130];
                    resv = ClientSVControlBlock_getResv(cb);
                    e = e ? e : ClientSVControlBlock_getLastComError(cb);
                    snprintf(ref, sizeof(ref), "%s.UsvID", argv[i + 1]);
                    id = IedConnection_readStringValue(con, &err, ref, IEC61850_FC_US);
                    e = e ? e : err;
                }
                err = e;
                printf("svcb %s multicast=%d svena=%d resv=%d id=%s err=%d\n", argv[i + 1], mc, ena, resv,
                       id ? id : "", err);
                failed |= err != IED_ERROR_OK;
                free(id);
                ClientSVControlBlock_destroy(cb);
            }
            i += 1;
        }
        else if (strcmp(cmd, "svena") == 0 && i + 2 < argc) {
            ClientSVControlBlock cb = ClientSVControlBlock_create(con, argv[i + 1]);
            err = IED_ERROR_OBJECT_DOES_NOT_EXIST;
            if (cb) {
                ClientSVControlBlock_setSvEna(cb, atoi(argv[i + 2]) != 0);
                err = ClientSVControlBlock_getLastComError(cb);
                ClientSVControlBlock_destroy(cb);
            }
            printf("svena err=%d\n", err);
            failed |= err != IED_ERROR_OK;
            i += 2;
        }
        else if (strcmp(cmd, "svresv") == 0 && i + 2 < argc) {
            char ref[130];
            snprintf(ref, sizeof(ref), "%s.Resv", argv[i + 1]);
            IedConnection_writeBooleanValue(con, &err, ref, IEC61850_FC_US, atoi(argv[i + 2]) != 0);
            printf("svresv err=%d\n", err);
            failed |= err != IED_ERROR_OK;
            i += 2;
        }
        else {
            fprintf(stderr, "unknown command %s\n", cmd);
            failed = 1;
        }
        fflush(stdout);
    }

    IedConnection_destroy(con);
    return failed ? 1 : 0;
}
