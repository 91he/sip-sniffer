set(libnids_VERSION_MAJOR 1)
set(libnids_VERSION_MINOR 0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -D_BSD_SOURCE ${LIBNET_CFLAGS_OTHER}")

check_include_file("unistd.h" HAVE_UNISTD_H)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "(alpha|arm|hp|mips|sparc).*")
  set(LBL_ALIGN 1)
endif()

if(CMAKE_C_BYTE_ORDER EQUAL "BIG_ENDIAN")
  set(WORDS_BIGENDIAN 1)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/libnids/config.h.in"
  "${PROJECT_SOURCE_DIR}/libnids/config.h"
)

file(WRITE ${PROJECT_BINARY_DIR}/test/test_icmphdr.c "
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
int main() {
    struct icmphdr h;
    int c=h.type;
}")
try_compile(HAVE_ICMPHDR ${PROJECT_BINARY_DIR}/test ${PROJECT_BINARY_DIR}/test/test_icmphdr.c)
#file(REMOVE ${PROJECT_BINARY_DIR}/test/test_icmphdr.c)

if(HAVE_ICMPHDR)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_ICMPHDR=1")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_ICMPHDR=0")
endif()

file(WRITE ${PROJECT_BINARY_DIR}/test/test_udphdr.c "
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/udp.h>
int main() {
    struct udphdr h;
    int c=h.uh_ulen;
}")
try_compile(HAVE_BSD_UDPHDR ${PROJECT_BINARY_DIR}/test ${PROJECT_BINARY_DIR}/test/test_udphdr.c)
#file(REMOVE ${PROJECT_BINARY_DIR}/test/test_udphdr.c)

if(HAVE_BSD_UDPHDR)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_BSD_UDPHDR=1")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_BSD_UDPHDR=0")
endif()

if(LIBNET_VERSION GREATER_EQUAL "1.0")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBNET_VER=1")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLIBNET_VER=0")
endif()

file(WRITE ${PROJECT_BINARY_DIR}/test/test_tcpstate.c "
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
int main() {
    int c = TCP_ESTABLISHED;
}")
try_compile(HAVE_TCP_STATES ${PROJECT_BINARY_DIR}/test ${PROJECT_BINARY_DIR}/test/test_tcpstate.c)
#file(REMOVE ${PROJECT_BINARY_DIR}/test/test_tcpstate.c)
file(REMOVE_RECURSE ${PROJECT_BINARY_DIR}/test)

if(HAVE_TCP_STATES)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_TCP_STATES=1")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_TCP_STATES=0")
endif()

pkg_check_modules(LIBPCRE REQUIRED libpcre)
#string(REPLACE ";" " " LIBPCRE_LINK_LIBRARIES "${LIBPCRE_LINK_LIBRARIES}")

aux_source_directory(. SRC_LIST)
add_library(nids STATIC ${SRC_LIST})

#TARGET_LINK_LIBRARIES(nids ${GTHREAD_LINK_LIBRARIES} ${LIBNET_LINK_LIBRARIES} ${LIBPCRE_LINK_LIBRARIES})
target_include_directories(nids PUBLIC .)
target_include_directories(nids PUBLIC ${GTHREAD_INCLUDE_DIRS} ${LIBNET_INCLUDE_DIRS} ${LIBPCRE_INCLUDE_DIRS})
