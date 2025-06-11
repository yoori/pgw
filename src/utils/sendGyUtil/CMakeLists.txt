add_executable(sendGyUtil
  SendUtil.cpp
  )

target_link_libraries(sendGyUtil
  PUBLIC dpi Gears
  PRIVATE Threads::Threads
  )

#install(TARGETS sendUtil DESTINATION bin/utils)
