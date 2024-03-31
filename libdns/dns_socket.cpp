#include "dns_socket.h"

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#endif

#ifndef _WIN32
void closesocket(SOCKET s)
{
    close(s);
}
#endif

bool setupsocket(SOCKET fd)
{
   if (fd < 0) return false;

#ifdef _WIN32
   unsigned long mode = 1;
   return (ioctlsocket(fd, FIONBIO, &mode) == 0);
#else
   int option = 1;
   if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
   {
       return false;
   }
   int flags = fcntl(fd, F_GETFL, 0);
   if (flags == -1) return false;
   flags = flags | O_NONBLOCK;
   if (fcntl(fd, F_SETFL, flags) < 0)
   {
        return false;
   }
   return true;
#endif
}


