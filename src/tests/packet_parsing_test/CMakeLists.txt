add_executable(diameterPacketParseTest
  main.cpp
  )

target_link_libraries(diameterPacketParseTest
  PUBLIC DiameterPacketConstructor Gears event event_core ${LIBEVENT_LIBRARIES}
  PRIVATE Threads::Threads
  )
