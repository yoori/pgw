project(Gears)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# projects executable name
set(TARGET_NAME Gears)

set(
  GEARS_SOURCE_FILES
    src/StringManip.cpp
    src/AsciiStringManip.cpp
    src/Time.cpp
    src/Condition.cpp
    src/ActiveObject.cpp
    src/CompositeActiveObject.cpp
    src/IOContextActiveObject.cpp
    src/StringManip.cpp
    src/ThreadRunner.cpp
    src/TaskRunner.cpp
    src/Planner.cpp
    src/Time.cpp
    src/Logger.cpp
    src/StreamLogger.cpp
    src/SimpleLogger.cpp
    src/ActiveObjectCallback.cpp
    src/Rand.cpp
    src/Listener.cpp
    src/Singleton.cpp
    src/AppUtils.cpp
    src/TextTemplate.cpp
    src/MMap.cpp
    src/CRC.cpp
    src/PathManip.cpp
    src/UTF8Category.cpp
    src/UTF8IsDigit.cpp
    src/UTF8IsSpace.cpp
    src/UTF8IsLetter.cpp
    src/UTF8IsLowerLetter.cpp
    src/UTF8IsUpperLetter.cpp
    src/UTF8IsTitleLetter.cpp
    src/MemBuf.cpp
    src/Allocator.cpp
    src/UrlAddress.cpp
    src/UnicodeNormalizer.cpp
    src/UnicodeNormTables.cpp
)

include(FindPkgConfig)
pkg_search_module(LIBEVENT libevent)
find_package(Boost REQUIRED)

add_library(${TARGET_NAME} SHARED ${GEARS_SOURCE_FILES})

target_include_directories(${TARGET_NAME} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include/gears>
  )

target_link_libraries(${TARGET_NAME}
  ${LIBEVENT_LIBRARIES}
  ${CMAKE_THREAD_LIBS_INIT}
  Boost::boost
)

install(TARGETS ${TARGET_NAME} DESTINATION lib)
