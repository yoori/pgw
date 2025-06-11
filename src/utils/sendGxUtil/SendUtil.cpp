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

  Gears::AppUtils::OptionsSet<std::vector<std::string>> opt_source_addresses;

  args.add(Gears::AppUtils::equal_name("connect-host"), opt_connect_servers);
  args.add(Gears::AppUtils::equal_name("connect-port"), opt_connect_port);
  args.add(Gears::AppUtils::equal_name("local-host"), opt_local_servers);
  args.add(Gears::AppUtils::equal_name("local-port"), opt_local_port);

  args.add(Gears::AppUtils::equal_name("origin-host"), opt_origin_host);
  args.add(Gears::AppUtils::equal_name("origin-realm"), opt_origin_realm);
  args.add(Gears::AppUtils::equal_name("destination-host"), opt_destination_host);
  args.add(Gears::AppUtils::equal_name("destination-realm"), opt_destination_realm);

  args.add(Gears::AppUtils::equal_name("source-address"), opt_source_addresses);

  args.parse(argc - 1, argv + 1);

  try
  {
    std::vector<dpi::DiameterSession::Endpoint> local_endpoints;
    for (auto it = opt_local_servers->begin(); it != opt_local_servers->end(); ++it)
    {
      local_endpoints.emplace_back(dpi::DiameterSession::Endpoint(*it, *opt_local_port));
    }

    std::vector<dpi::DiameterSession::Endpoint> connect_endpoints;
    for (auto it = opt_connect_servers->begin(); it != opt_connect_servers->end(); ++it)
    {
      connect_endpoints.emplace_back(dpi::DiameterSession::Endpoint(*it, *opt_connect_port));
    }

    auto logger = std::make_shared<dpi::StreamLogger>(std::cout);

    std::shared_ptr<dpi::DiameterSession> session = std::make_shared<dpi::DiameterSession>(
      logger,
      local_endpoints,
      connect_endpoints,
      *opt_origin_host,
      *opt_origin_realm,
      !opt_destination_host->empty() ? std::optional<std::string>(*opt_destination_host) : std::nullopt,
      !opt_destination_realm->empty() ? std::optional<std::string>(*opt_destination_realm) : std::nullopt,
      16777238, //< Gx
      "3GPP Gx",
      true,
      *opt_source_addresses
      );

    dpi::DiameterSession::Request request;
    request.msisdn = "79662660021";
    //request.service_id = 1; // TO FILL
    request.framed_ip_address = ipv4(10, 243, 64, 1);
    request.nas_ip_address = ipv4(10, 77, 21, 116);
    request.imsi = "250507712932915";
    request.rat_type = 1004;
    request.mcc_mnc = "25020";
    request.timezone = 33;
    request.sgsn_ip_address = ipv4(185, 77, 17, 121);
    request.access_network_charging_ip_address = ipv4(185, 174, 131, 53);
    request.charging_id = 0x4188491;

    dpi::DiameterSession::GxInitResponse gx_init_response = session->send_gx_init(request);
    std::cout << "Gx init request: result-code: " << gx_init_response.result_code << std::endl;

    dpi::DiameterSession::GxUpdateRequest gx_update_request;
    gx_update_request.usage_monitorings.emplace_back(
      dpi::DiameterSession::GxUpdateRequest::UsageMonitoring(
        64, //< Internet: MK64
        1000 //< bytes
      )
    );
    gx_update_request.usage_monitorings.emplace_back(
      dpi::DiameterSession::GxUpdateRequest::UsageMonitoring(
        161, //< Telegram: MK161
        1000 //< bytes
      )
    );
    dpi::DiameterSession::GxUpdateResponse gx_update_response = session->send_gx_update(request, gx_update_request);
    std::cout << "Gx update request: result-code: " << gx_init_response.result_code << std::endl;

    dpi::DiameterSession::GxTerminateRequest gx_terminate_request;
    dpi::DiameterSession::GxTerminateResponse gx_terminate_response = session->send_gx_terminate(request, gx_terminate_request);
    std::cout << "Gx terminate request: result-code: " << gx_terminate_response.result_code << std::endl;
  }
  catch(const Gears::Exception& ex)
  {
    std::cerr << "[ERROR] Send failed: " << ex.what() << std::endl;
  }

  return 0;
}
