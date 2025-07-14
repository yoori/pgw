#include <iostream>

#include <dpi/Types.hpp>
#include <dpi/User.hpp>
#include <dpi/ShapingManager.hpp>
#include <dpi/NetInterfaceProcessor.hpp>

class TestUserSessionPacketProcessor: public dpi::UserSessionPacketProcessor
{
public:
  virtual void process_user_session_packet(
    dpi::PacketProcessingState& processing_state,
    const Gears::Time& time,
    const dpi::UserPtr& user,
    const dpi::FlowTraits& flow_traits,
    dpi::Direction direction,
    const dpi::SessionKey& session_key,
    uint64_t packet_size,
    const void* packet) override
  {}
};

class TestNetInterface: public dpi::NetInterface
{
public:
  TestNetInterface()
    : NetInterface("test_interface")
  {}

  virtual pcap_t* pcap_handle() const override
  {
    return nullptr;
  }

  virtual void send(const void* packet_buf, int packet_buf_size) override
  {
    std::cout << "[" << Gears::Time::get_time_of_day().gm_ft() << "] "
      "send packet, size = " << packet_buf_size << std::endl;
  }
};

int main()
{
  auto user_session_packet_processor = std::make_shared<TestUserSessionPacketProcessor>();
  auto shaping_manager = std::make_shared<dpi::ShapingManager>(user_session_packet_processor);
  shaping_manager->activate_object();

  auto send_interface = std::make_shared<TestNetInterface>();

  dpi::SessionRuleConfig session_rule_config;
  session_rule_config.clear_closed_sessions_timeout = Gears::Time::ONE_DAY;
  session_rule_config.default_rule.close_timeout = Gears::Time(30);

  const Gears::Time start_time = Gears::Time::get_time_of_day();
  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("89263411124"));

  const dpi::SessionKey key1("test1", "");
  const dpi::SessionKey key2("test2", "");

  std::vector<dpi::SessionKey> shape_session_keys{key1, key2};

  user->set_shaping(shape_session_keys, 1000);

  std::cout << "--- time step 1 ---" << std::endl;

  {
    auto state1 = user->process_packet(session_rule_config, key1, start_time, 1000);
    std::cout << "state1.shaped = " << state1.shaped << std::endl;

    auto state2 = user->process_packet(session_rule_config, key2, start_time, 1000);
    std::cout << "state2.shaped = " << state2.shaped << std::endl;

    if (state2.shaped)
    {
      shaping_manager->add_shaped_packet(
        start_time,
        user,
        dpi::FlowTraits(),
        dpi::Direction::D_NONE,
        key2,
        0,
        nullptr, //< packet buffer
        send_interface);
    }

    auto state3 = user->process_packet(session_rule_config, key2, start_time, 1000);
    std::cout << "state3.shaped = " << state3.shaped << std::endl;
  }

  std::cout << "--- time step 2 ---" << std::endl;

  {
    auto state1 = user->process_packet(session_rule_config, key2, start_time + Gears::Time::ONE_SECOND, 1000);
    std::cout << "state1.shaped = " << state1.shaped << std::endl;

    auto state2 = user->process_packet(session_rule_config, key2, start_time + Gears::Time::ONE_SECOND, 1000);
    std::cout << "state2.shaped = " << state2.shaped << std::endl;
  }

  sleep(10);

  shaping_manager->deactivate_object();
  shaping_manager->wait_object();

  return 0;
}
