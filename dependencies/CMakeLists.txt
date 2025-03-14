add_subdirectory(gears)
add_subdirectory(DiameterPacketConstructor)
add_subdirectory(jsoncons)

set(nDPI_DESTDIR ${CMAKE_CURRENT_BINARY_DIR}/build/nDPI_install)

ExternalProject_Add(nDPIBuild
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/nDPI
  CONFIGURE_COMMAND
    COMMAND bash -c "cd <SOURCE_DIR> ; ./autogen.sh --enable-debug-build"
  BUILD_COMMAND make VERBOSE=1
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
  INSTALL_COMMAND mkdir -p "${nDPI_DESTDIR}"
    COMMAND bash -c "make install DESTDIR=${nDPI_DESTDIR}"
)

add_library(nDPI INTERFACE)
target_include_directories(nDPI INTERFACE
  ${nDPI_DESTDIR}/usr/include
  ${nDPI_DESTDIR}/usr/include/ndpi
  ${CMAKE_CURRENT_SOURCE_DIR}/nDPI/src/lib/third_party/include
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(pcap REQUIRED libpcap)

target_link_libraries(nDPI INTERFACE
  ${nDPI_DESTDIR}/usr/lib64/libndpi.a
  pcap
)

add_dependencies(nDPI nDPIBuild)


set(ENV{LIBMICROHTTPD_CFLAGS} "")
set(ENV{LIBMICROHTTPD_LIBS} "")

ExternalProject_Add(libhttpserver_ext
  URL "https://github.com/etr/libhttpserver/archive/refs/tags/0.19.0.tar.gz"
  PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libhttpserver
  CONFIGURE_COMMAND bash -c "pushd <SOURCE_DIR>/ && ./bootstrap && popd && <SOURCE_DIR>/configure --enable-debug --disable-examples --prefix=/"
  BUILD_COMMAND bash -c "make DESTDIR='${CMAKE_BINARY_DIR}/libhttpserver-install' install"
  INSTALL_COMMAND ""
  )

SET(LIBHTTPSERVER_LIB_DIR ${CMAKE_BINARY_DIR}/libhttpserver-install/lib)
add_library(libhttpserver INTERFACE)
target_link_libraries(libhttpserver INTERFACE ${LIBHTTPSERVER_LIB_DIR}/libhttpserver.so.0.19.0)
target_include_directories(libhttpserver INTERFACE ${CMAKE_BINARY_DIR}/libhttpserver-install/include)
install(FILES ${LIBHTTPSERVER_LIB_DIR}/libhttpserver.so.0.19.0 DESTINATION lib)
install(FILES ${LIBHTTPSERVER_LIB_DIR}/libhttpserver.so.0.19.0 DESTINATION lib RENAME libhttpserver.so.0)
