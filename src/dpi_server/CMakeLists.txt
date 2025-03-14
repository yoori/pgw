add_executable(dpi_server
  DPIServer.cpp
  )

target_link_libraries(dpi_server
  PRIVATE
    nDPI
    Gears
    dpi
    http_server
  )
