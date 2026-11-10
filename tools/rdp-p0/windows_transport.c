#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <iphlpapi.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <freerdp/freerdp.h>
#include "probe.h"

// Refuse alternate peers, redirections, and a source address on any other adapter.
int windows_mesh_connect(const char *host, int port, uint16_t expected_port, DWORD timeout) {
    const char *source = getenv("CALABI_RDP_LOCAL");
    const char *expected = getenv("CALABI_P0_PEER");
    struct sockaddr_in local = {0}, peer = {0};
    local.sin_family = peer.sin_family = AF_INET;
    peer.sin_port = htons(expected_port);
    if (!source || !expected || !host || strcmp(host, expected) || !expected_port || port != expected_port ||
        InetPtonA(AF_INET, source, &local.sin_addr) != 1 ||
        InetPtonA(AF_INET, host, &peer.sin_addr) != 1) return -1;
    ULONG size = 0, index = 0;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, NULL, &size) != ERROR_BUFFER_OVERFLOW) return -1;
    IP_ADAPTER_ADDRESSES *list = malloc(size);
    if (!list) return -1;
    if (GetAdaptersAddresses(AF_INET, flags, NULL, list, &size) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *a = list; a; a = a->Next) {
            if (!a->FriendlyName || _wcsicmp(a->FriendlyName, L"calabi-mesh") || a->OperStatus != IfOperStatusUp) continue;
            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
                const struct sockaddr_in *addr = (const struct sockaddr_in *)u->Address.lpSockaddr;
                if (addr && addr->sin_family == AF_INET && addr->sin_addr.s_addr == local.sin_addr.s_addr) index = a->IfIndex;
            }
        }
    }
    free(list);
    if (!index) return -1;
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) return -1;
    DWORD iface = htonl(index);
    u_long nonblocking = 1;
    if (fd > INT_MAX || setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, (const char *)&iface, sizeof(iface)) ||
        bind(fd, (struct sockaddr *)&local, sizeof(local)) || ioctlsocket(fd,FIONBIO,&nonblocking)) goto fail;
    if (connect(fd,(struct sockaddr *)&peer,sizeof(peer))) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) goto fail;
        WSAPOLLFD poll = {fd, POLLWRNORM, 0};
        int err = 0, len = sizeof(err);
        ULONGLONG deadline = GetTickCount64() + (timeout && timeout<10000 ? timeout : 10000);
        int status = 0;
        while (!probe_requested_stop() && GetTickCount64() < deadline &&
               (status = WSAPoll(&poll,1,100)) == 0) {}
        if (status<=0 || probe_requested_stop() ||
            getsockopt(fd,SOL_SOCKET,SO_ERROR,(char *)&err,&len) || err) goto fail;
    }
    nonblocking = 0;
    if (ioctlsocket(fd,FIONBIO,&nonblocking)) goto fail;
    // FreeRDP enables SO_KEEPALIVE, but does not set its Windows timings.
    struct tcp_keepalive keepalive = {1, 5000, 2000};
    DWORD bytes = 0;
    WSAIoctl(fd,SIO_KEEPALIVE_VALS,&keepalive,sizeof(keepalive),NULL,0,&bytes,NULL,NULL);
#ifdef TCP_KEEPCNT
    DWORD probes = 3;
    setsockopt(fd,IPPROTO_TCP,TCP_KEEPCNT,(const char *)&probes,sizeof(probes));
#endif
    return (int)fd;
fail:
    closesocket(fd); return -1;
}
