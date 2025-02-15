project(Gears)

# projects executable name
set(TARGET_NAME Gears)

set(
  GEARS_SOURCE_FILES
    StringManip.cpp
    AsciiStringManip.cpp
    Time.cpp
    Condition.cpp
    ActiveObject.cpp
    CompositeActiveObject.cpp 
    StringManip.cpp
    ThreadRunner.cpp
    TaskRunner.cpp
    Planner.cpp
    Time.cpp
    Logger.cpp
    StreamLogger.cpp
    SimpleLogger.cpp
    ActiveObjectCallback.cpp
    Rand.cpp
    Listener.cpp
    Singleton.cpp
    AppUtils.cpp
    TextTemplate.cpp
    MMap.cpp
    CRC.cpp
    PathManip.cpp
    UTF8Category.cpp
    UTF8IsDigit.cpp
    UTF8IsSpace.cpp
    UTF8IsLetter.cpp
    UTF8IsLowerLetter.cpp
    UTF8IsUpperLetter.cpp
    UTF8IsTitleLetter.cpp
    MemBuf.cpp
    Allocator.cpp
)

add_library(${TARGET_NAME} STATIC ${GEARS_SOURCE_FILES})

target_link_libraries(${TARGET_NAME}
  ${LIBEVENT_LIB}
  ${CMAKE_THREAD_LIBS_INIT})

target_include_directories(${TARGET_NAME}
  PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/../"
  INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/../"
)

#install(TARGETS ${TARGET_NAME} DESTINATION lib)
