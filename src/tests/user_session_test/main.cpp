#include <iostream>
#include <sstream>

#include <dpi/UserSession.hpp>

using namespace dpi;

std::string used_limits_to_string(const dpi::UserSession::UsedLimitArray& used_limits)
{
  std::ostringstream ostr;
  for (auto it = used_limits.begin(); it != used_limits.end(); ++it)
  {
    ostr << (it != used_limits.begin() ? ", " : "") << "{" <<
      "session_key = " << it->session_key.to_string() <<
      ", total_octets = " << it->total_octets <<
      ", output_octets = " << it->output_octets <<
      ", input_octets = " << it->input_octets <<
      "}";
  }

  return ostr.str();
}

bool test_no_limits()
{
  static const char* TEST_NAME = "no limits";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);
  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(10, 10, 0));
  
  if (!res.block || res.revalidate_gx || res.revalidate_gy)
  {
    std::cerr << TEST_NAME << ": unexpected result on step #1: " << res.to_string() << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

bool test_pass_by_limit()
{
  static const char* TEST_NAME = "pass by limit check";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt
    )
  );

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(10, 10, 0));

  if (!res.block || res.revalidate_gx || res.revalidate_gy)
  {
    std::cerr << TEST_NAME << ": non blocked packet, " << res.to_string() << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

bool test_block_by_limit()
{
  static const char* TEST_NAME = "block by limit check";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      std::nullopt,
      1000,
      std::nullopt,
      std::nullopt,
      2000
    )
  );

  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(1500, 0, 0));

  //std::cout << "T: " << res.to_string() << std::endl;

  if (!res.block)
  {
    std::cerr << TEST_NAME << ": non blocked packet" << std::endl;
    return false;
  }

  if (res.revalidate_gx || res.revalidate_gy)
  {
    std::cerr << TEST_NAME << ": unexpected result: " << res.to_string() << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

// test_use_and_block_by_limit
bool test_use_and_block_by_limit()
{
  static const char* TEST_NAME = "use and block by limit check";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      std::nullopt,
      1000,
      std::nullopt, 
      std::nullopt,
      2000
    )
  );

  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(100, 0, 0));

  if (res.block)
  {
    std::cerr << TEST_NAME << ": step1 - expected non blocked packet, " <<
      res.to_string() << std::endl;
    return false;
  }

  auto used_limits = user_session.get_gy_used_limits();

  if (used_limits.size() != 1 || used_limits.begin()->total_octets != 100)
  {
    std::cerr << TEST_NAME << ": step2 - unexpected used limits: " <<
      used_limits_to_string(used_limits) <<
      std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(910, 0, 0));

  if (!res.block)
  {
    std::cerr << TEST_NAME << ": step3 - expected blocked packet" << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

// test_gx_flow
bool test_gx_flow()
{
  static const char* TEST_NAME = "gx flow";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      std::nullopt,
      1000,
      std::nullopt,
      std::nullopt,
      2000
    )
  );

  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(100, 0, 0));

  if (res.block)
  {
    std::cerr << TEST_NAME << ": step1 - expected non blocked packet" << std::endl;
    return false;
  }

  auto used_limits = user_session.get_gy_used_limits();

  if (used_limits.size() != 1 || used_limits.begin()->total_octets != 100)
  {
    std::cerr << TEST_NAME << ": step2 - unexpected used limits: " <<
      used_limits_to_string(used_limits) <<
      std::endl;
    return false;
  }

  user_session.set_limits(limits, used_limits);

  auto last_used_limits = user_session.get_gy_used_limits();

  if (!last_used_limits.empty())
  {
    std::cerr << TEST_NAME << ": step2 - unexpected used limits: " <<
      used_limits_to_string(used_limits) <<
      std::endl;
    return false;
  }

  //
  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(110, 0, 0));

  user_session.set_limits(limits);

  auto last_used_limits2 = user_session.get_gy_used_limits();

  if (last_used_limits2.size() != 1 || last_used_limits2.begin()->total_octets != 110)
  {
    std::cerr << TEST_NAME << ": step3 - unexpected used limits: " <<
      used_limits_to_string(used_limits) <<
      std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

// test_pass_by_generic_limit
bool test_pass_by_generic_limit()
{
  static const char* TEST_NAME = "pass by generic limit check";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey(),
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      100000
    )
  );
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      0
    )
  );
  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    OctetStats(10, 0, 0));

  if (res.block)
  {
    std::cerr << TEST_NAME << ": blocked packet" << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

// revalidate_gx_by_time_test
bool revalidate_gx_by_time_test()
{
  static const char* TEST_NAME = "revalidate gx by time test";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  Gears::Time start_time = Gears::Time::get_time_of_day();

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey(),
      start_time + Gears::Time(10),
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt,
      100000
    )
  );
  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time,
    OctetStats(10, 0, 0));

  if (res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 1" << std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time + Gears::Time(9),
    OctetStats(10, 0, 0));

  if (res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 2" << std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time + Gears::Time(11),
    OctetStats(10, 0, 0));

  if (!res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 3" << std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time + Gears::Time(11),
    OctetStats(10, 0, 0));

  if (res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 4" << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

// revalidate_gx_by_limit_test
bool revalidate_gx_by_limit_test()
{
  static const char* TEST_NAME = "revalidate gx by limit test";

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), nullptr, user);

  Gears::Time start_time = Gears::Time::get_time_of_day();

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey(),
      std::nullopt,
      10000,
      100000,
      std::nullopt,
      std::nullopt,
      std::nullopt
    )
  );
  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time,
    OctetStats(9998, 0, 0));

  if (res.block || res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 1, " << res.to_string() << std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time + Gears::Time(9),
    OctetStats(1000, 0, 0));

  if (res.block || !res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 2, " << res.to_string() << std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time + Gears::Time(11),
    OctetStats(1000, 0, 0));

  if (res.block || res.revalidate_gx)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 3, " << res.to_string() << std::endl;
    return false;
  }

  // Used 11998
  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    start_time + Gears::Time(11),
    OctetStats(990000, 0, 0));

  if (!res.block)
  {
    std::cerr << TEST_NAME << ": unexpected gx revalidate on step 4, " << res.to_string() << std::endl;
    return false;
  }

  std::cout << TEST_NAME << ": success" << std::endl;
  return true;
}

int main()
{
  bool res = true;

  if (!test_no_limits())
  {
    res = false;
  }

  if (!test_pass_by_limit())
  {
    res = false;
  }

  if (!test_block_by_limit())
  {
    res = false;
  }

  if (!test_use_and_block_by_limit())
  {
    res = false;
  }

  if (!test_gx_flow())
  {
    res = false;
  }

  if (!test_pass_by_generic_limit())
  {
    res = false;
  }

  if (!revalidate_gx_by_time_test())
  {
    res = false;
  }

  if (!revalidate_gx_by_limit_test())
  {
    res = false;
  }

  return res ? 0 : -1;
}
