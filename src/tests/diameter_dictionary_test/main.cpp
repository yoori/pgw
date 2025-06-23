#include <iostream>
#include <sstream>

#include <gears/AppUtils.hpp>

#include <dpi/DiameterDictionary.hpp>


bool test_diameter_avp_path(dpi::DiameterDictionary& dictionary)
{
  static const char* TEST_NAME = "diameter avp path";

  auto avp_path = dictionary.get_request_avp_path(272, "Multiple-Services-Credit-Control.Rating-Group");
  if (!avp_path.has_value())
  {
    std::cerr << "AVP Path is null" << std::endl;
    return false;
  }

  std::cout << "Res: " << avp_path->to_string() << std::endl;
  return true;
}

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_dict;
  args.add(Gears::AppUtils::equal_name("dict"), opt_dict);

  args.parse(argc - 1, argv + 1);

  dpi::DiameterDictionary dictionary(*opt_dict);

  bool res = true;

  if (!test_diameter_avp_path(dictionary))
  {
    res = false;
  }

  return res ? 0 : -1;
}
