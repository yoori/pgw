#include <iostream>
#include <sstream>

#include <gears/AppUtils.hpp>

#include <dpi/DiameterPacketFiller.hpp>


bool test1(dpi::DiameterDictionary& dictionary)
{
  dpi::DiameterPacketFiller filler(dictionary, 272);

  filler.add_avp(
    "Service-Information.PS-Information.3GPP-GPRS-Negotiated-QoS-Profile",
    dpi::Value(std::in_place_type<uint64_t>, 0xA0A0A0A0));

  /*
  filler.add_avp("User-Equipment-Info.User-Equipment-Info-Value", dpi::Value(std::string("11111")));
  filler.add_avp("RAT-Type", dpi::Value(std::in_place_type<uint64_t>, 11111));
  filler.add_avp("Service-Information.PS-Information.SGSN-Address", dpi::Value(std::in_place_type<uint64_t>, 0xA0A0A0A0));
  */

  /*
  dpi::Value val;
  val.emplace<int64_t>(11111);
  filler.add_avp("User-Equipment-Info.User-Equipment-Info-Value", val);
  */

  Diameter::Packet packet = Diameter::Packet()
    .setHeader(
    Diameter::Packet::Header()
      // Setting that it's request 
      .setCommandFlags(
         Diameter::Packet::Header::Flags()
         .setFlag(Diameter::Packet::Header::Flags::Bits::Request, true)
      )
      .setCommandCode(272)
      .setApplicationId(0)
      .setHBHIdentifier(0x00000ad1)
      .setETEIdentifier(0x00000ad1)
   );

  filler.apply(packet);

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

  if (!test1(dictionary))
  {
    res = false;
  }

  return res ? 0 : -1;
}
