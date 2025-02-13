#include <iostream>

extern "C" {
#include "impl.h"
}

void tel_gateway_process_request()
{
  std::cout << "tel_gateway_process_request" << std::endl;
}

void tel_gateway_initialize()
{
  std::cout << "tel_gateway_initialize" << std::endl;
}

void tel_gateway_load()
{
  std::cout << "tel_gateway_load" << std::endl;
}

void tel_gateway_unload()
{
  std::cout << "tel_gateway_unload" << std::endl;
}
