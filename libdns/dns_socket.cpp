#include "dns_socket.h"

#include <stdexcept>
#include <utility>

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

void setupsocket(SOCKET s)
{
   if (s < 0)
   {
      throw std::runtime_error("setupsocket error: invalid socket");
   }

#ifdef _WIN32
   unsigned long mode = 1;
   if (ioctlsocket(s, FIONBIO, &mode) != 0)
   {
      throw std::runtime_error("setupsocket error: ioctlsocket()");
   }
#else
   int option = 1;
   if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0)
   {
       throw std::runtime_error("setupsocket error: setsockopt()");
   }
   int flags = fcntl(s, F_GETFL, 0);
   if (flags == -1)
   {
      throw std::runtime_error("setupsocket error: fcntl(F_GETFL)");
   }
   flags = flags | O_NONBLOCK;
   if (fcntl(s, F_SETFL, flags) < 0)
   {
        throw std::runtime_error("setupsocket error: fcntl(F_SETFL)");
   }
#endif
}


