add_executable(sendUtil
  SendUtil.cpp
  )

target_link_libraries(sendUtil
  PUBLIC DiameterPacketConstructor Gears event event_core ${LIBEVENT_LIBRARIES}
  PRIVATE Threads::Threads
  )

#install(TARGETS sendUtil DESTINATION bin/utils)
