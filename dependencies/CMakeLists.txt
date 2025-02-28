add_subdirectory(gears)
add_subdirectory(DiameterPacketConstructor)

set(nDPI_DESTDIR ${CMAKE_CURRENT_BINARY_DIR}/build/nDPI_install)

ExternalProject_Add(nDPI
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/nDPI
  CONFIGURE_COMMAND
    COMMAND bash -c "cd <SOURCE_DIR> ; ./autogen.sh"
  BUILD_COMMAND ${MAKE}
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
  INSTALL_COMMAND mkdir -p "${nDPI_DESTDIR}"
    COMMAND bash -c "make install DESTDIR=${nDPI_DESTDIR}"
)
