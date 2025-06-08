add_executable(radius_server main.cpp server.cpp)

target_link_libraries(radius_server
  PRIVATE
    OpenSSL::Crypto
    Boost::boost
    Threads::Threads
    Gears
    radproto
)
