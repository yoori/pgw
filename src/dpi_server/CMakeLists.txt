add_executable(dpi_server
  DPIServer.cpp
  PacketProcessor.cpp
  ReaderUtil.cpp
  NetworkUtils.cpp
  Config.cpp
  )

target_link_libraries(dpi_server
  PRIVATE
    nDPI
    Gears
  )
