add_executable(net_bridge
  NetBridge.cpp
  )

target_link_libraries(net_bridge
  PRIVATE
    nDPI
    Gears
    dpi
  )
