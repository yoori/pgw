add_library(http_server
  HttpServer.cpp
  Utils.cpp
  UserGetHttpResource.cpp
  UserAddHttpResource.cpp
  UserSessionAddHttpResource.cpp
  UserBlockHttpResource.cpp
  SetEventActionHttpResource.cpp
  UserSetShapingHttpResource.cpp
  AbortSessionHttpResource.cpp
  UpdateSessionHttpResource.cpp
  UserSessionAddHttpResource.cpp
  UserSessionGetHttpResource.cpp
  )

target_link_libraries(http_server
  PUBLIC
    dpi
    Gears
    libhttpserver
    jsoncons
  )

target_include_directories(http_server
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../
  )
