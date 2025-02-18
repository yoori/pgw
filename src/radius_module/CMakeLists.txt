add_library(radius_module SHARED
  impl.cpp
  Processor.cpp
  AVPUtils.cpp
  DiameterSession.cpp
  )

target_link_libraries(radius_module
  PUBLIC
    DiameterPacketConstructor
    Gears
  )

target_include_directories(radius_module
  INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../"
)
