#include <stdio.h>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iomanip>

#include "StatsDumper.hpp"

namespace dpi
{
  StatsDumper::StatsDumper(std::string ch_dump_path)
    : ch_dump_path_(ch_dump_path)
  {}

  PacketProcessingState
  StatsDumper::process_user_session_packet(
    const Gears::Time& time,
    const UserPtr& user,
    uint32_t src_ip,
    uint32_t dst_ip,
    const SessionKey& session_key,
    uint64_t packet_size)
  {
    detailed_stat_collector_.add_record(
      StatKey(
        time,
        session_key.traffic_type,
        user ? user->msisdn() : std::string()
        ),
      StatValue(
        1,
        packet_size
        ));

    return PacketProcessingState();
  }

  std::pair<std::string, std::string>
  StatsDumper::generate_file_name_(const std::string& prefix)
  {
    static const char DATE_FMT[] = "%Y%m%d.%H%M%S.%q";
    std::ostringstream ostr;
    long rand_value = static_cast<long int>(99999999. * (random() / (RAND_MAX + 1.))) + 1;
    ostr << prefix << "." << Gears::Time::get_time_of_day().get_gm_time().format(DATE_FMT) <<
      "." << std::setfill('0') << std::setw(8) << rand_value << ".csv";
    return std::make_pair(std::string("~") + ostr.str(), ostr.str());
  }

  void
  StatsDumper::dump()
  {
    {
      // dump detailed
      std::pair<std::string, std::string> fp = generate_file_name_("DetailedStat");
      if(detailed_stat_collector_.dump(ch_dump_path_ + "/" + fp.first))
      {
        ::rename((ch_dump_path_ + "/" + fp.first).c_str(), (ch_dump_path_ + "/" + fp.second).c_str());
      }
    }
  }
}
