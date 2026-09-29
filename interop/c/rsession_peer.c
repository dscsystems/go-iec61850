/*
 * rsession_peer: drives libiec61850's R-GOOSE and R-SV (IEC 61850-90-5
 * session protocol) from the command line, for the interop suite.
 *
 *   rsession_peer MODE ADDR PORT KEYID KEYHEX SECALGO SIGALGO COUNT
 *
 * MODE     goose-pub | goose-sub | sv-pub | sv-sub
 * ADDR     publisher: destination address; subscriber: address to bind
 * PORT     UDP port (a publisher sends to it, a subscriber binds it)
 * KEYID    key identifier (0 = no key, unsecured)
 * KEYHEX   the key, hex encoded ("-" for none)
 * SECALGO  0 none, 1 AES-128-GCM, 2 AES-256-GCM
 * SIGALGO  0 none, 1 HMAC-SHA256-80, 2 HMAC-SHA256-128, 3 HMAC-SHA256-256
 * COUNT    messages to send, or to receive before exiting (a subscriber
 *          also exits after 5 s)
 *
 * A publisher sends a fixed data set a subscriber can check: GOOSE
 * gocbRef "GOISIM/LLN0$GO$gcb1", data set {INT32 1234, BOOLEAN true,
 * VISIBLE-STRING "r-goose"}, APPID 0x3001; SV svID "RSV1", two FLOAT32
 * 1.5 and -2.25, smpCnt counting from 0, APPID 0x4001. A subscriber
 * prints one line per message: "GOOSE st=.. sq=.. data=.." or
 * "SV svID=.. smpCnt=.. v0=.. v1=..".
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "goose_publisher.h"
#include "goose_receiver.h"
#include "goose_subscriber.h"
#include "hal_thread.h"
#include "hal_time.h"
#include "r_session.h"
#include "sv_publisher.h"
#include "sv_subscriber.h"

static int received = 0;

static int
hexKey(const char* hex, uint8_t* out, int max)
{
    int n = 0;
    if (strcmp(hex, "-") == 0)
        return 0;
    while (hex[0] && hex[1] && n < max) {
        unsigned int b;
        if (sscanf(hex, "%2x", &b) != 1)
            return -1;
        out[n++] = (uint8_t) b;
        hex += 2;
    }
    return n;
}

static void
gooseListener(GooseSubscriber sub, void* param)
{
    char buf[1024];
    MmsValue_printToBuffer(GooseSubscriber_getDataSetValues(sub), buf, sizeof(buf));
    printf("GOOSE st=%u sq=%u valid=%d data=%s\n", GooseSubscriber_getStNum(sub),
           GooseSubscriber_getSqNum(sub), GooseSubscriber_isValid(sub) ? 1 : 0, buf);
    fflush(stdout);
    received++;
}

static void
svListener(SVSubscriber sub, void* param, SVSubscriber_ASDU asdu)
{
    printf("SV svID=%s smpCnt=%u v0=%g v1=%g\n", SVSubscriber_ASDU_getSvId(asdu),
           SVSubscriber_ASDU_getSmpCnt(asdu), SVSubscriber_ASDU_getFLOAT32(asdu, 0),
           SVSubscriber_ASDU_getFLOAT32(asdu, 4));
    fflush(stdout);
    received++;
}

int
main(int argc, char** argv)
{
    if (argc != 9) {
        fprintf(stderr, "usage: %s MODE ADDR PORT KEYID KEYHEX SECALGO SIGALGO COUNT\n", argv[0]);
        return 2;
    }
    const char* mode = argv[1];
    const char* addr = argv[2];
    int port = atoi(argv[3]);
    uint32_t keyId = (uint32_t) strtoul(argv[4], NULL, 10);
    uint8_t key[64];
    int keyLen = hexKey(argv[5], key, sizeof(key));
    RSecurityAlgorithm sec = (RSecurityAlgorithm) atoi(argv[6]);
    RSignatureAlgorithm sig = (RSignatureAlgorithm) atoi(argv[7]);
    int count = atoi(argv[8]);

    if (keyLen < 0) {
        fprintf(stderr, "bad key\n");
        return 2;
    }

    RSession session = RSession_create();
    if (keyId != 0) {
        RSession_addKey(session, keyId, key, keyLen, sec, sig);
        RSession_setActiveKey(session, keyId);
    }

    if (strcmp(mode, "goose-pub") == 0 || strcmp(mode, "sv-pub") == 0) {
        RSession_setLocalAddress(session, "0.0.0.0", 0);
        RSession_setRemoteAddress(session, addr, port);

        if (mode[0] == 'g') {
            LinkedList values = LinkedList_create();
            LinkedList_add(values, MmsValue_newIntegerFromInt32(1234));
            LinkedList_add(values, MmsValue_newBoolean(true));
            LinkedList_add(values, MmsValue_newVisibleString("r-goose"));
            GoosePublisher pub = GoosePublisher_createRemote(session, 0x3001);
            GoosePublisher_setGoCbRef(pub, "GOISIM/LLN0$GO$gcb1");
            GoosePublisher_setDataSetRef(pub, "GOISIM/LLN0$DS1");
            GoosePublisher_setGoID(pub, "GOISIM");
            GoosePublisher_setConfRev(pub, 1);
            GoosePublisher_setTimeAllowedToLive(pub, 2000);
            RSession_start(session);
            for (int i = 0; i < count; i++) {
                if (GoosePublisher_publish(pub, values) == -1)
                    fprintf(stderr, "publish failed\n");
                Thread_sleep(50);
            }
            GoosePublisher_destroy(pub);
        }
        else {
            SVPublisher pub = SVPublisher_createRemote(session, 0x4001);
            SVPublisher_ASDU asdu = SVPublisher_addASDU(pub, "RSV1", NULL, 1);
            int f0 = SVPublisher_ASDU_addFLOAT(asdu);
            int f1 = SVPublisher_ASDU_addFLOAT(asdu);
            SVPublisher_setupComplete(pub);
            RSession_start(session);
            for (int i = 0; i < count; i++) {
                SVPublisher_ASDU_setFLOAT(asdu, f0, 1.5f);
                SVPublisher_ASDU_setFLOAT(asdu, f1, -2.25f);
                SVPublisher_ASDU_setSmpCnt(asdu, (uint16_t) i);
                SVPublisher_publish(pub);
                Thread_sleep(50);
            }
            SVPublisher_destroy(pub);
        }
        printf("sent %d\n", count);
        return 0;
    }

    RSession_setLocalAddress(session, addr, port);
    uint64_t deadline = Hal_getTimeInMs() + 5000;

    if (strcmp(mode, "goose-sub") == 0) {
        GooseReceiver rcv = GooseReceiver_createRemote(session);
        GooseSubscriber sub = GooseSubscriber_create("GOISIM/LLN0$GO$gcb1", NULL);
        GooseSubscriber_setAppId(sub, 0x3001);
        GooseSubscriber_setListener(sub, gooseListener, NULL);
        GooseReceiver_addSubscriber(rcv, sub);
        GooseReceiver_start(rcv);
        if (!GooseReceiver_isRunning(rcv)) {
            fprintf(stderr, "receiver did not start\n");
            return 1;
        }
        printf("listening\n");
        fflush(stdout);
        while (received < count && Hal_getTimeInMs() < deadline)
            Thread_sleep(20);
        GooseReceiver_stop(rcv);
    }
    else if (strcmp(mode, "sv-sub") == 0) {
        SVReceiver rcv = SVReceiver_createRemote(session);
        SVSubscriber sub = SVSubscriber_create(NULL, 0x4001);
        SVSubscriber_setListener(sub, svListener, NULL);
        SVReceiver_addSubscriber(rcv, sub);
        SVReceiver_start(rcv);
        if (!SVReceiver_isRunning(rcv)) {
            fprintf(stderr, "receiver did not start\n");
            return 1;
        }
        printf("listening\n");
        fflush(stdout);
        while (received < count && Hal_getTimeInMs() < deadline)
            Thread_sleep(20);
        SVReceiver_stop(rcv);
    }
    else {
        fprintf(stderr, "unknown mode %s\n", mode);
        return 2;
    }
    printf("received %d\n", received);
    return received >= count ? 0 : 1;
}
