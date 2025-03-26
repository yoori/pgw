add_library(radius_module SHARED
  impl.cpp
  Processor.cpp
  )

target_link_libraries(radius_module
  PRIVATE
    sctp
  PUBLIC
    DiameterPacketConstructor
    Gears
    dpi
    http_server
  )

# dpi

target_include_directories(radius_module
  INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../"
)
