set(CMAKE_CXX_COMPILER "/usr/bin/clang++-11")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -stdlib=libc++")

pkg_check_modules(LIBPCAP libpcap)
if(NOT LIBPCAP_FOUND)
  message(FATAL_ERROR "no required package: libpcap")
endif()

string(REPLACE ";" " " GTHREAD_LDFLAGS "${GTHREAD_LDFLAGS}")
string(REPLACE ";" " " LIBPCAP_LDFLAGS "${LIBPCAP_LDFLAGS}")
#target_link_libraries(sip-sniffer ${LIBNET_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBPCAP_LDFLAGS})
#target_link_libraries(sip-sniffer ${PROJECT_BINARY_DIR}/libnids/libnids.a)
link_libraries(${PROJECT_BINARY_DIR}/libnids/libnids.a)
link_libraries(${LIBNET_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBPCAP_LDFLAGS})

#target_include_directories(sip-sniffer PUBLIC .)
#target_include_directories(sip-sniffer PUBLIC ${PROJECT_SOURCE_DIR}/libnids)
include_directories(.)
include_directories(${PROJECT_SOURCE_DIR}/libnids)

aux_source_directory(. SRC_LIST)

set(CGO_CFLAGS "-I${PROJECT_SOURCE_DIR}/libnids")
set(CGO_LDFLAGS "-L${PROJECT_BINARY_DIR}/libnids -lnids ${LIBNET_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBPCAP_LDFLAGS}")
add_custom_target(goss ALL COMMAND ${CMAKE_COMMAND} -E env CGO_CFLAGS=${CGO_CFLAGS} CGO_LDFLAGS=${CGO_LDFLAGS} go build -o goss sip-sniffer/src/cmd)
#add_executable(sip-sniffer ./printall.cpp)
#add_executable(sniff ./sniff.c)
