add_library(http_server
  HttpServer.cpp
  Utils.cpp
  UserGetHttpResource.cpp
  UserAddHttpResource.cpp
  )

target_link_libraries(http_server
  PUBLIC
    Gears
    libhttpserver
    jsoncons
  )

target_include_directories(http_server
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../
  )
