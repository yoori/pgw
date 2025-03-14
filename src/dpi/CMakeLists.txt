add_library(dpi
  DPIRunner.cpp
  Config.cpp
  NetworkUtils.cpp
  PacketProcessor.cpp
  ReaderUtil.cpp
  UserStorage.cpp
  User.cpp
  Logger.cpp
  NetInterface.cpp
  )

target_link_libraries(dpi
  PUBLIC
    nDPI
    Gears
    libhttpserver
    jsoncons
  )

target_include_directories(dpi
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../
  )
