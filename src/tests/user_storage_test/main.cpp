#include <iostream>

#include <dpi/UserStorage.hpp>


int main()
{
  auto event_logger = std::make_shared<dpi::StreamLogger>(std::cout);
  auto user_storage = std::make_shared<dpi::UserStorage>(event_logger);
  user_storage->add_user("89263411124", 1);

  return 0;
}
