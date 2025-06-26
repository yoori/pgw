add_executable(pgw_server
  PGWServer.cpp
  Processor.cpp
  RadiusServer.cpp
  RadiusServerImpl.cpp
  )

target_link_libraries(pgw_server
  PRIVATE
    nDPI
    Gears
    dpi
    http_server
    radproto
  )
