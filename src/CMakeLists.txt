# Use bash, radius install don't work in sh
set(radius_DESTDIR ${CMAKE_CURRENT_BINARY_DIR}/build/radius_install)

add_subdirectory(radius_module)
add_subdirectory(dpi)
add_subdirectory(dpi_server)
add_subdirectory(utils)
add_subdirectory(tests)

ExternalProject_Add(radius
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/radius
  CONFIGURE_COMMAND
    COMMAND bash -c "LDFLAGS=-L${CMAKE_BINARY_DIR}/lib/ <SOURCE_DIR>/configure \
      --enable-developer \
      --with-openssl-include-dir=/usr/include/openssl3/ --with-openssl-lib-dir=/usr/lib64/openssl3/ \
      --prefix=${INSTALL_PREFIX}"
  BUILD_COMMAND ${MAKE}
  BUILD_IN_SOURCE 1
  BUILD_ALWAYS 1
  INSTALL_COMMAND mkdir -p "${radius_DESTDIR}"
    COMMAND bash -c "make install R=${radius_DESTDIR}"
    COMMAND find "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/sites-enabled/" -type f -delete
    COMMAND find "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/sites-enabled/" -type l -delete
    COMMAND rm "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/clients.conf"
    COMMAND rm -rf "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/mods-enabled/eap"
    COMMAND rm -rf "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/mods-enabled/eap_inner"
    COMMAND cp ${CMAKE_SOURCE_DIR}/data/raddb/mods-available/sber "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/mods-enabled/"
    COMMAND cp ${CMAKE_SOURCE_DIR}/data/raddb/clients.conf "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/"
    COMMAND cp ${CMAKE_SOURCE_DIR}/data/raddb/site "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/sites-enabled/"
    COMMAND cp ${CMAKE_SOURCE_DIR}/data/raddb/gateway_config.json "${radius_DESTDIR}/${INSTALL_PREFIX}/etc/raddb/"
  DEPENDS radius_module
)

install(
  DIRECTORY ${radius_DESTDIR}/
  DESTINATION "."
  USE_SOURCE_PERMISSIONS
)
