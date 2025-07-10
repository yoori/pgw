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
  return b4 << 24 | b3 << 16 | b2 << 8 | b1;
}

dpi::UserSessionPropertyContainerPtr fill_user_session_property_container()
{
  dpi::UserSessionPropertyContainerPtr user_session_property_container =
    std::make_shared<dpi::UserSessionPropertyContainer>();
  user_session_property_container->values.emplace(
    "Framed-IP-Address",
    dpi::Value(std::in_place_type<uint64_t>, ipv4(10, 243, 64, 1)));
  user_session_property_container->values.emplace(
    "SGSN-Address",
    dpi::Value(std::in_place_type<uint64_t>, ipv4(185, 77, 17, 121)));
  user_session_property_container->values.emplace(
    "CG-Address",
    dpi::Value(std::in_place_type<uint64_t>, ipv4(185, 174, 131, 53)));
  user_session_property_container->values.emplace(
    "CG-Address",
    dpi::Value(std::in_place_type<uint64_t>, ipv4(185, 174, 131, 53)));
  user_session_property_container->values.emplace(
    "Charging-ID",
    dpi::Value(std::in_place_type<uint64_t>, 0x4188491));
  user_session_property_container->values.emplace(
    "RAT-Type",
    dpi::Value(std::in_place_type<uint64_t>, 6));
  user_session_property_container->values.emplace(
    "MS-TimeZone",
    dpi::Value(std::in_place_type<uint64_t>, 33));
  user_session_property_container->values.emplace(
    "SGSN-MCC-MNC",
    std::string("25020"));
  user_session_property_container->values.emplace(
    "Called-Station-Id",
    std::string("internet.sberbank-tele.com"));
  /*
  user_session_property_container->values.emplace(
    "Charging-Characteristics",
    std::string());
  user_session_property_container->values.emplace(
    "Selection-Mode",
    std::string());
  user_session_property_container->values.emplace(
    "NSAPI",
    std::string());
  */
  const unsigned char USER_LOCATION_INFO[] = {
    0x82, 0x52, 0xf0, 0x02, 0x6c, 0x9a, 0x52, 0xf0, 0x02, 0x0b, 0xcd, 0xc0, 0x23
  };
  user_session_property_container->values.emplace(
    "User-Location-Info",
    dpi::ByteArrayValue(USER_LOCATION_INFO, USER_LOCATION_INFO + sizeof(USER_LOCATION_INFO)));
  user_session_property_container->values.emplace(
    "GPRS-Negotiated-QoS-profile",
    std::string("08-48080000c350000249f0"));
  user_session_property_container->values.emplace(
    "IMEI",
    dpi::Value(std::string("33353732343837373930353932323031")));

  // Constants
  user_session_property_container->values.emplace(
    "Serving-Node-Type",
    dpi::Value(std::in_place_type<uint64_t>, 2));
  user_session_property_container->values.emplace(
    "PDP-Type",
    dpi::Value(std::in_place_type<uint64_t>, 0));
  user_session_property_container->values.emplace(
    "PDP-Context-Type",
    dpi::Value(std::in_place_type<uint64_t>, 0));
  user_session_property_container->values.emplace(
    "IMSI",
    std::string("250507712932915"));

  return user_session_property_container;
}

std::vector<dpi::DiameterPassAttribute> fill_gx_pass_attributes()
{
  std::vector<dpi::DiameterPassAttribute> pass_attributes;
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Framed-IP-Address",
    "Framed-IP-Address",
    "ipv4-as-4bytes"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Called-Station-Id",
    "Called-Station-Id"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "RAT-Type",
    "RAT-Type"
    // TODO : adapter from 3GPP-RAT-Type values to RAT-Type, radius contains : 6, 3GPP-RAT-Type (gy) : 6, RAT-Type (gx) : 1004
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "3GPP-User-Location-Info",
    "User-Location-Info"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "3GPP-SGSN-MCC-MNC",
    "SGSN-MCC-MNC"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "3GPP-SGSN-Address",
    "SGSN-Address",
    "ipv4-as-4bytes"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "AN-GW-Address",
    "SGSN-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "AN-GW-Address",
    "SGSN-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Access-Network-Charging-Address",
    "CG-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "3GPP-MS-TimeZone",
    "MS-TimeZone",
    "timezone-as-2bytes"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Access-Network-Charging-Identifier-Gx.Access-Network-Charging-Identifier-Value",
    "Charging-ID",
    "to-string"
  ));

  return pass_attributes;
}

std::vector<dpi::DiameterPassAttribute> fill_gy_pass_attributes()
{
  std::vector<dpi::DiameterPassAttribute> pass_attributes;
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.PDP-Address",
    "Framed-IP-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.SGSN-Address",
    "SGSN-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.CG-Address",
    "SGSN-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.GGSN-Address",
    "CG-Address"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-Charging-Id",
    "Charging-ID"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-PDP-Type",
    "PDP-Type"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.PDP-Context-Type",
    "PDP-Context-Type"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-RAT-Type",
    "RAT-Type",
    "int-as-1byte"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.PDN-Connection-Charging-ID",
    "Charging-ID"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.Serving-Node-Type",
    "Serving-Node-Type"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-MS-TimeZone",
    "MS-TimeZone",
    "timezone-as-2bytes"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.Called-Station-Id",
    "Called-Station-Id"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-GGSN-MCC-MNC",
    "SGSN-MCC-MNC"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-SGSN-MCC-MNC",
    "SGSN-MCC-MNC"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-IMSI-MCC-MNC",
    "SGSN-MCC-MNC"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-Charging-Characteristics",
    "Charging-Characteristics"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-Selection-Mode",
    "Selection-Mode"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-NSAPI",
    "NSAPI"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-User-Location-Info",
    "User-Location-Info"
  ));
  pass_attributes.emplace_back(dpi::DiameterPassAttribute(
    "Service-Information.PS-Information.3GPP-GPRS-Negotiated-QoS-Profile",
    "GPRS-Negotiated-QoS-profile"
  ));
  return pass_attributes;
}

int main(int argc, char* argv[])
{
  Gears::AppUtils::Args args;
  Gears::AppUtils::StringOption opt_origin_host("localhost");
  Gears::AppUtils::StringOption opt_origin_realm("localhost");
  Gears::AppUtils::StringOption opt_destination_host;
  Gears::AppUtils::StringOption opt_destination_realm;
  Gears::AppUtils::CheckOption opt_use_filler;

  Gears::AppUtils::OptionsSet<std::vector<std::string>> opt_local_servers;
  Gears::AppUtils::Option<unsigned int> opt_local_port(0);

  Gears::AppUtils::OptionsSet<std::vector<std::string>> opt_connect_servers;
  Gears::AppUtils::Option<unsigned int> opt_connect_port(3869);

  Gears::AppUtils::OptionsSet<std::vector<std::string>> opt_source_addresses;
  Gears::AppUtils::StringOption opt_dict;

  args.add(Gears::AppUtils::equal_name("connect-host"), opt_connect_servers);
  args.add(Gears::AppUtils::equal_name("connect-port"), opt_connect_port);
  args.add(Gears::AppUtils::equal_name("local-host"), opt_local_servers);
  args.add(Gears::AppUtils::equal_name("local-port"), opt_local_port);

  args.add(Gears::AppUtils::equal_name("origin-host"), opt_origin_host);
  args.add(Gears::AppUtils::equal_name("origin-realm"), opt_origin_realm);
  args.add(Gears::AppUtils::equal_name("destination-host"), opt_destination_host);
  args.add(Gears::AppUtils::equal_name("destination-realm"), opt_destination_realm);

  args.add(Gears::AppUtils::equal_name("source-address"), opt_source_addresses);
  args.add(Gears::AppUtils::equal_name("dict"), opt_dict);
  args.add(Gears::AppUtils::equal_name("use-filler"), opt_use_filler);

  args.parse(argc - 1, argv + 1);

  try
  {
    dpi::DiameterDictionary dictionary(*opt_dict);

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

    dpi::SCTPDiameterSession::make_exchange(
      *sctp_connection,
      *opt_origin_host,
      *opt_origin_realm,
      !opt_destination_host->empty() ? std::optional<std::string>(*opt_destination_host) : std::nullopt,
      !opt_destination_realm->empty() ? std::optional<std::string>(*opt_destination_realm) : std::nullopt,
      "Traflab PGW",
      std::vector<uint32_t>({16777238, 4}),
      *opt_source_addresses
    );

    /*
    while (true)
    {
      sctp_connection->connect();
      sleep(1);
    }
    */

    /*
    auto gx_connection = std::make_shared<dpi::SCTPStreamConnection>(
      sctp_connection,
      1);
    */
    auto gx_connection = sctp_connection;

    dpi::UserSessionPropertyContainerPtr user_session_property_container =
      fill_user_session_property_container();

    std::vector<dpi::DiameterPassAttribute> gx_pass_attributes;

    std::shared_ptr<dpi::SCTPDiameterSession> session = std::make_shared<dpi::SCTPDiameterSession>(
      logger,
      dictionary,
      gx_connection,
      *opt_origin_host,
      *opt_origin_realm,
      !opt_destination_host->empty() ? std::optional<std::string>(*opt_destination_host) : std::nullopt,
      !opt_destination_realm->empty() ? std::optional<std::string>(*opt_destination_realm) : std::nullopt,
      16777238, //< Gx
      "PGW", //"3GPP Gx",
      [](const Diameter::Packet&) {},
      *opt_source_addresses,
      fill_gx_pass_attributes(),
      fill_gy_pass_attributes()
      );

    session->activate_object();

    dpi::UserSessionTraits user_session_traits;
    user_session_traits.user_session_property_container = user_session_property_container;
    user_session_traits.msisdn = "79662660021";
    //user_session_traits.called_station_id = "ltpcef.test";
    user_session_traits.framed_ip_address = ipv4(10, 243, 64, 1);
    //user_session_traits.nas_ip_address = ipv4(10, 77, 21, 116);
    //user_session_traits.imsi = "250507712932915";

    const unsigned long GX_APPLICATION_ID = 16777238;
    const std::string GX_SESSION_ID_SUFFIX = ";1;0;1";
    unsigned int gx_request_i = 0;

    dpi::DiameterSession::Request request;
    request.application_id = GX_APPLICATION_ID;
    request.session_id_suffix = GX_SESSION_ID_SUFFIX;
    request.request_id = gx_request_i++;
    request.user_session_traits = user_session_traits;

    dpi::DiameterSession::GxInitResponse gx_init_response = session->send_gx_init(request);
    std::cout << "Gx init request: result-code: " << gx_init_response.result_code << ", charging_rule_names = [";
    for (auto it = gx_init_response.install_charging_rule_names.begin(); it != gx_init_response.install_charging_rule_names.end(); ++it)
    {
      std::cout << (it != gx_init_response.install_charging_rule_names.begin() ? " ": "") << *it;
    }
    std::cout << "]" << std::endl;

    // UPDATE
    request.request_id = gx_request_i++;
    dpi::DiameterSession::GxUpdateRequest gx_update_request;

    gx_update_request.usage_monitorings.emplace_back(
      dpi::DiameterSession::GxUpdateRequest::UsageMonitoring(
        64, //< Internet: MK64
        dpi::OctetStats(1000, 0, 0) //< bytes
      )
    );
    gx_update_request.usage_monitorings.emplace_back(
      dpi::DiameterSession::GxUpdateRequest::UsageMonitoring(
        161, //< Telegram: MK161
        dpi::OctetStats(1000, 0, 0) //< bytes
      )
    );

    gx_update_request.not_found_charging_rule_names.emplace("TESTING-NOT-FOUND-RULE");

    dpi::DiameterSession::GxUpdateResponse gx_update_response = session->send_gx_update(
      request, gx_update_request);
    std::cout << "Gx update request: result-code: " << gx_init_response.result_code << std::endl;

    // TERMINATE
    request.request_id = gx_request_i++;

    dpi::DiameterSession::GxTerminateRequest gx_terminate_request;
    dpi::DiameterSession::GxTerminateResponse gx_terminate_response = session->send_gx_terminate(
      request, gx_terminate_request);
    std::cout << "Gx terminate request: result-code: " << gx_terminate_response.result_code << std::endl;

    std::cout << "====== SEND GY ======" << std::endl;
    const unsigned long GY_APPLICATION_ID = 4;
    const std::string GY_SESSION_ID_SUFFIX = ";2;0;1";
    unsigned int gy_request_i = 0;

    {
      //const unsigned char USER_LOCATION_INFO[] = {
      //  0x82, 0x52, 0xf0, 0x02, 0x6c, 0x9a, 0x52, 0xf0, 0x02, 0x0b, 0xcd, 0xc0, 0x23
      //};

      dpi::DiameterSession::GyRequest request;
      request.application_id = GY_APPLICATION_ID;
      request.session_id_suffix = GY_SESSION_ID_SUFFIX;
      request.request_id = gy_request_i++;

      request.user_session_traits = user_session_traits;
      request.usage_rating_groups.emplace_back(dpi::DiameterSession::GyRequest::UsageRatingGroup(32)); // Internet(MVNO_SBT_UNLIM): RG32 MK64
      request.usage_rating_groups.emplace_back(dpi::DiameterSession::GyRequest::UsageRatingGroup(61)); //

      dpi::DiameterSession::GyResponse gy_init_response = session->send_gy_init(request);
      std::cout << "Gy init request: result-code = " << gy_init_response.result_code <<
        "  rating_group_limits:" << std::endl;
      for (const auto& rating_group : gy_init_response.rating_group_limits)
      {
        std::cout << "    " << rating_group.to_string() << std::endl;
      }
      //std::cout << std::endl;

      request.request_id = gy_request_i++;
      dpi::DiameterSession::GyResponse gy_update_response = session->send_gy_update(request);

      request.request_id = gy_request_i++;
      dpi::DiameterSession::GyResponse gy_terminate_response = session->send_gy_terminate(request);
    }

    std::cout << "====== STOP ======" << std::endl;

    ::sleep(1);
    std::cout << "To stop" << std::endl;

    session->deactivate_object();
    //gy_session->deactivate_object();
    session->wait_object();
    //gy_session->wait_object();
  }
  catch(const Gears::Exception& ex)
  {
    std::cerr << "[ERROR] Send failed: " << ex.what() << std::endl;
  }

  return 0;
}
