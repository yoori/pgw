add_executable(sendUtil2
  SendUtil.cpp
  )

target_link_libraries(sendUtil2
  PUBLIC radius_module Gears
  PRIVATE Threads::Threads
  )

#install(TARGETS sendUtil DESTINATION bin/utils)
