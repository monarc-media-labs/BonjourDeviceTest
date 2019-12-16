/*
To build this tool, copy and paste the following into a command line:

OS X:
gcc dns-sd.c -o dns-sd

POSIX systems:
gcc dns-sd.c -o dns-sd -I../mDNSShared -ldns_sd

Windows:
cl dns-sd.c -I../mDNSShared -DNOT_HAVE_GETOPT ws2_32.lib ..\mDNSWindows\DLL\Release\dnssd.lib
(may require that you run a Visual Studio script such as vsvars32.bat first)
*/

// For testing changes to dnssd_clientstub.c, uncomment this line and the code will be compiled
// with an embedded copy of the client stub instead of linking the system library version at runtime.
// This also useful to work around link errors when you're working on an older version of Mac OS X,
// and trying to build a newer version of the "dns-sd" command which uses new API entry points that
// aren't in the system's /usr/lib/libSystem.dylib.
//#define TEST_NEW_CLIENTSTUB 1

// When building mDNSResponder for Mac OS X 10.4 and earlier, /usr/lib/libSystem.dylib is built using its own private
// copy of dnssd_clientstub.c, which is old and doesn't have all the entry points defined in the latest version, so
// when we're building dns-sd.c on Mac OS X 10.4 or earlier, we automatically set TEST_NEW_CLIENTSTUB so that we'll
// embed a copy of the latest dnssd_clientstub.c instead of trying to link to the incomplete version in libSystem.dylib
#if defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ <= 1040
#define TEST_NEW_CLIENTSTUB 1
#endif

#include <ctype.h>
#include <stdio.h>			// For stdout, stderr
#include <stdlib.h>			// For exit()
#include <string.h>			// For strlen(), strcpy()
#include <errno.h>			// For errno, EINTR
#include <time.h>
#include <sys/types.h>		// For u_char

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Iphlpapi.h>
#include <process.h>
typedef int        pid_t;
#define getpid     _getpid
#define strcasecmp _stricmp
#define snprintf   _snprintf
static const char kFilePathSep = '\\';
#ifndef HeapEnableTerminationOnCorruption
#     define HeapEnableTerminationOnCorruption (HEAP_INFORMATION_CLASS)1
#endif
#if !defined(IFNAMSIZ)
#define IFNAMSIZ 16
#endif

typedef PCHAR(WINAPI * if_indextoname_funcptr_t)(ULONG index, PCHAR name);
typedef ULONG(WINAPI* if_nametoindex_funcptr_t)(PCSTR name);

static size_t _sa_len(const struct sockaddr* addr)
{
    if (addr->sa_family == AF_INET) return (sizeof(struct sockaddr_in));
    else if (addr->sa_family == AF_INET6) return (sizeof(struct sockaddr_in6));
    else return (sizeof(struct sockaddr));
}

#   define SA_LEN(addr) (_sa_len(addr))

#else
#include <unistd.h>			// For getopt() and optind
#include <netdb.h>			// For getaddrinfo()
#include <sys/time.h>		// For struct timeval
#include <sys/socket.h>		// For AF_INET
#include <netinet/in.h>		// For struct sockaddr_in()
#include <arpa/inet.h>		// For inet_addr()
#include <net/if.h>			// For if_nametoindex()
static const char kFilePathSep = '/';
// #ifndef NOT_HAVE_SA_LEN
// 	#define SA_LEN(addr) ((addr)->sa_len)
// #else
#define SA_LEN(addr) (((addr)->sa_family == AF_INET6)? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))
// #endif
#endif

#if (TEST_NEW_CLIENTSTUB && !defined(__APPLE_API_PRIVATE))
#define __APPLE_API_PRIVATE 1
#endif

// DNSServiceSetDispatchQueue is not supported on 10.6 & prior
#if ! TEST_NEW_CLIENTSTUB && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__) && (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ - (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ % 10) <= 1060)
#undef _DNS_SD_LIBDISPATCH
#endif
#include "dns_sd.h"

#if TEST_NEW_CLIENTSTUB
#include "../mDNSShared/dnssd_ipc.c"
#include "../mDNSShared/dnssd_clientlib.c"
#include "../mDNSShared/dnssd_clientstub.c"
#endif

//*************************************************************************************************************
// Globals

typedef union
{
    unsigned char b[2];
    unsigned short NotAnInteger;
} Opaque16;

static uint32_t opinterface = kDNSServiceInterfaceIndexAny;
static DNSServiceRef client = NULL;
static DNSServiceRef client_pa = NULL;	// DNSServiceRef for RegisterProxyAddressRecord

#if _DNS_SD_LIBDISPATCH
dispatch_queue_t main_queue;
dispatch_source_t timer_source;
#endif

// Note: the select() implementation on Windows (Winsock2) fails with any timeout much larger than this
#define LONG_TIME 100000000

static volatile int stopNow = 0;
static volatile int timeOut = LONG_TIME;

#if _DNS_SD_LIBDISPATCH
#define EXIT_IF_LIBDISPATCH_FATAL_ERROR(E) \
	if (main_queue && (E) == kDNSServiceErr_ServiceNotRunning) { fprintf(stderr, "Error code %d\n", (E)); exit(0); }
#else
#define EXIT_IF_LIBDISPATCH_FATAL_ERROR(E)
#endif

//*************************************************************************************************************
// Sample callback functions

static void printtimestamp(void)
{
    struct tm tm;
    int ms;
#ifdef _WIN32
    SYSTEMTIME sysTime;
    time_t uct = time(NULL);
    tm = *localtime(&uct);
    GetLocalTime(&sysTime);
    ms = sysTime.wMilliseconds;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    localtime_r((time_t*)& tv.tv_sec, &tm);
    ms = tv.tv_usec / 1000;
#endif
    printf("%2d:%02d:%02d.%03d  ", tm.tm_hour, tm.tm_min, tm.tm_sec, ms);
}

static void myTimerCallBack(void)
{
    printf("myTimerCallBack\n\r");
}

static void DNSSD_API reg_reply(DNSServiceRef sdref, const DNSServiceFlags flags, DNSServiceErrorType errorCode,
                                const char* name, const char* regtype, const char* domain, void* context)
{
    (void)sdref;    // Unused
    (void)flags;    // Unused
    (void)context;  // Unused
    EXIT_IF_LIBDISPATCH_FATAL_ERROR(errorCode);

    printtimestamp();
    printf("Got a reply for service %s.%s%s: ", name, regtype, domain);

    if (errorCode == kDNSServiceErr_NoError)
    {
        if (flags & kDNSServiceFlagsAdd)
        {
            printf("Name now registered and active\n");
        }
        else
        {
            printf("Name registration removed\n");
        }
    }
    else if (errorCode == kDNSServiceErr_NameConflict)
    {
        printf("Name in use, please choose another\n");
        exit(-1);
    }
    else
    {
        printf("Error %d\n", errorCode);
    }

    if (!(flags & kDNSServiceFlagsMoreComing))
    {
        fflush(stdout);
    }
}



//*************************************************************************************************************
// The main test function

static void HandleEvents(void)
#if _DNS_SD_LIBDISPATCH
{
    main_queue = dispatch_get_main_queue();
    if (client)  DNSServiceSetDispatchQueue(client, main_queue);
    if (client_pa)  DNSServiceSetDispatchQueue(client_pa, main_queue);
    dispatch_main();
}
#else
{
    int dns_sd_fd = client ? DNSServiceRefSockFD(client) : -1;
    int dns_sd_fd2 = client_pa ? DNSServiceRefSockFD(client_pa) : -1;
    int nfds = dns_sd_fd + 1;
    fd_set readfds;
    struct timeval tv;
    int result;

    if (dns_sd_fd2 > dns_sd_fd) nfds = dns_sd_fd2 + 1;

    while (!stopNow)
    {
        // 1. Set up the fd_set as usual here.
        // This example client has no file descriptors of its own,
        // but a real application would call FD_SET to add them to the set here
        FD_ZERO(&readfds);

        // 2. Add the fd for our client(s) to the fd_set
        if (client) FD_SET(dns_sd_fd, &readfds);
        if (client_pa) FD_SET(dns_sd_fd2, &readfds);

        // 3. Set up the timeout.
        tv.tv_sec = timeOut;
        tv.tv_usec = 0;

        result = select(nfds, &readfds, (fd_set*)NULL, (fd_set*)NULL, &tv);
        if (result > 0)
        {
            DNSServiceErrorType err = kDNSServiceErr_NoError;
            if (client && FD_ISSET(dns_sd_fd, &readfds)) err = DNSServiceProcessResult(client);
            else if (client_pa && FD_ISSET(dns_sd_fd2, &readfds)) err = DNSServiceProcessResult(client_pa);
            if (err) { fprintf(stderr, "DNSServiceProcessResult returned %d\n", err); stopNow = 1; }
        }
        else if (result == 0)
            myTimerCallBack();
        else
        {
            printf("select() returned %d errno %d %s\n", result, errno, strerror(errno));
            if (errno != EINTR) stopNow = 1;
        }
    }
}
#endif


int main(int argc, char** argv)
{
    DNSServiceErrorType err;
    DNSServiceFlags flags = 0;

    Opaque16 registerPort = {{ 0x27, 0x10 }};
    static const char TXT[] = "\x9" "txtvers=1" "\xB" "protovers=1" "\x1A" "modelGUID=0000130e00000008";
    printf("Registering Service Test._testupdate._tcp.local.\n");
    err = DNSServiceRegister(&client, 0, opinterface, "Sottovoce Engine", "_oca._tcp.", "", NULL, registerPort.NotAnInteger, sizeof(TXT) - 1, TXT, reg_reply, NULL);

    if (!client || err != kDNSServiceErr_NoError)
    {
        fprintf(stderr, "DNSService call failed %ld\n", (long int)err); return (-1);
    }
    HandleEvents();
    // Be sure to deallocate the DNSServiceRef when you're finished
    if (client)
    {
        DNSServiceRefDeallocate(client);
    }
    if (client_pa)
    {
        DNSServiceRefDeallocate(client_pa);
    }
    return 0;
}