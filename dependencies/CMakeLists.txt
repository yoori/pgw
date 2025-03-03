add_subdirectory(gears)
add_subdirectory(DiameterPacketConstructor)

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
