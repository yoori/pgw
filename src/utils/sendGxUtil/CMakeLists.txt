add_executable(sendGxUtil
  SendUtil.cpp
  )

target_link_libraries(sendGxUtil
  PUBLIC dpi Gears
  PRIVATE Threads::Threads
  )

#install(TARGETS sendUtil DESTINATION bin/utils)
