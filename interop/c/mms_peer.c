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
 *   dir                 file directory              -> "file NAME SIZE" per file
 *   release             release (MMS conclude)      -> "release err=E"
 *   abort               abort                       -> "abort err=E"
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
        else {
            fprintf(stderr, "unknown command %s\n", cmd);
            failed = 1;
        }
        fflush(stdout);
    }

    IedConnection_destroy(con);
    return failed ? 1 : 0;
}
