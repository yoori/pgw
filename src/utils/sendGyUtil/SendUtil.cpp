#include <vector>
#include <memory>
#include <thread>
#include <atomic>

#include <gears/Time.hpp>
#include <gears/Rand.hpp>
#include <gears/StringManip.hpp>
#include <gears/AppUtils.hpp>

#include <dpi/DiameterSession.hpp>

std::atomic<int> req_count(0);

uint32_t ipv4(unsigned char b1, unsigned char b2, unsigned char b3, unsigned char b4)
{
  return b1 << 24 | b2 << 16 | b3 << 8 | b4;
}

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_origin_host("localhost");
  Gears::AppUtils::StringOption opt_origin_realm("localhost");
  Gears::AppUtils::StringOption opt_destination_host;
  Gears::AppUtils::StringOption opt_destination_realm;

  Gears::AppUtils::OptionsSet<std::vector<std::string>> opt_local_servers;
  Gears::AppUtils::Option<unsigned int> opt_local_port(0);

  Gears::AppUtils::OptionsSet<std::vector<std::string>> opt_connect_servers;
  Gears::AppUtils::Option<unsigned int> opt_connect_port(3869);

  args.add(Gears::AppUtils::equal_name("connect-host"), opt_connect_servers);
  args.add(Gears::AppUtils::equal_name("connect-port"), opt_connect_port);
  args.add(Gears::AppUtils::equal_name("local-host"), opt_local_servers);
  args.add(Gears::AppUtils::equal_name("local-port"), opt_local_port);

  args.add(Gears::AppUtils::equal_name("origin-host"), opt_origin_host);
  args.add(Gears::AppUtils::equal_name("origin-realm"), opt_origin_realm);
  args.add(Gears::AppUtils::equal_name("destination-host"), opt_destination_host);
  args.add(Gears::AppUtils::equal_name("destination-realm"), opt_destination_realm);
  args.parse(argc - 1, argv + 1);

  try
  {
    std::vector<dpi::SCTPConnection::Endpoint> local_endpoints;
    for (auto it = opt_local_servers->begin(); it != opt_local_servers->end(); ++it)
    {
      local_endpoints.emplace_back(dpi::SCTPConnection::Endpoint(*it, *opt_local_port));
    }

    std::vector<dpi::SCTPConnection::Endpoint> connect_endpoints;
    for (auto it = opt_connect_servers->begin(); it != opt_connect_servers->end(); ++it)
    {
      connect_endpoints.emplace_back(dpi::SCTPConnection::Endpoint(*it, *opt_connect_port));
    }

    auto logger = std::make_shared<dpi::StreamLogger>(std::cout);

    auto sctp_connection = std::make_shared<dpi::SCTPConnection>(
      logger,
      local_endpoints,
      connect_endpoints
    );

    sctp_connection->connect();

    sleep(10);

    std::shared_ptr<dpi::DiameterSession> session = std::make_shared<dpi::DiameterSession>(
      logger,
      sctp_connection,
      *opt_origin_host,
      *opt_origin_realm,
      !opt_destination_host->empty() ? std::optional<std::string>(*opt_destination_host) : std::nullopt,
      !opt_destination_realm->empty() ? std::optional<std::string>(*opt_destination_realm) : std::nullopt,
      4, //< DCCA = 4
      "Diameter Credit Control Application"
      );

    session->activate_object();

    dpi::DiameterSession::GyRequest request;
    request.user_session_traits.msisdn = "79662660021";
    request.user_session_traits.imsi = "250507712932915";
    request.user_session_traits.framed_ip_address = ipv4(10, 243, 64, 1);
    request.user_session_traits.nas_ip_address = ipv4(10, 77, 21, 116);
    request.user_session_traits.rat_type = 1004;
    request.user_session_traits.mcc_mnc = "25020";
    request.user_session_traits.timezone = 33;
    request.user_session_traits.sgsn_ip_address = ipv4(185, 77, 17, 121);
    request.user_session_traits.access_network_charging_ip_address = ipv4(185, 174, 131, 53);
    request.user_session_traits.charging_id = 0x4188491;
    request.user_session_traits.gprs_negotiated_qos_profile = "08-48080000c350000249f0"; // 08-48080000c350000249f0
    request.usage_rating_groups.emplace_back(dpi::DiameterSession::GyRequest::UsageRatingGroup(32)); // Internet(MVNO_SBT_UNLIM): RG32 MK64

    dpi::DiameterSession::GyResponse gy_init_response = session->send_gy_init(request);
    std::cout << "Gy init request: result-code: " << gy_init_response.result_code << std::endl;

    ::sleep(100);

    session->deactivate_object();
    session->wait_object();
  }
  catch(const Gears::Exception& ex)
  {
    std::cerr << "[ERROR] Send failed: " << ex.what() << std::endl;
  }

  return 0;
}
