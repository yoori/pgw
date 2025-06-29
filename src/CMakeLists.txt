# Use bash, radius install don't work in sh
set(radius_DESTDIR ${CMAKE_CURRENT_BINARY_DIR}/build/radius_install)

#add_subdirectory(radius_server)
#add_subdirectory(radius_module)
add_subdirectory(dpi)
#add_subdirectory(dpi_server)
add_subdirectory(utils)
add_subdirectory(tests)
add_subdirectory(http_server)
add_subdirectory(net_bridge)
add_subdirectory(pgw_server)

install(
  DIRECTORY ${radius_DESTDIR}/
  DESTINATION "."
  USE_SOURCE_PERMISSIONS
)
