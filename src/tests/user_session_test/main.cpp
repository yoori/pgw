#include <iostream>
#include <sstream>

#include <dpi/UserSession.hpp>

std::string used_limits_to_string(const dpi::UserSession::UsedLimitArray& used_limits)
{
  std::ostringstream ostr;
  for (auto it = used_limits.begin(); it != used_limits.end(); ++it)
  {
    ostr << (it != used_limits.begin() ? ", " : "") << "{" <<
      "session_key = " << it->session_key.to_string() <<
      ", used_bytes = " << it->used_bytes <<
      "}";
  }

  return ostr.str();
}

bool test_no_limits()
{
  static const char* TEST_NAME = "no limits";

  Gears::Time now = Gears::Time::get_time_of_day();

  dpi::UserPtr user = std::make_shared<dpi::User>(std::string("111"));
  dpi::UserSession user_session(dpi::UserSessionTraits(), user);
  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    10, 0, 0);
  if (!res.block)
  {
    std::cerr << TEST_NAME << ": non blocked packet" << std::endl;
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
  dpi::UserSession user_session(dpi::UserSessionTraits(), user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      std::nullopt,
      std::nullopt,
      std::nullopt
    )
  );

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    10, 0, 0);

  if (!res.block)
  {
    std::cerr << TEST_NAME << ": non blocked packet" << std::endl;
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
  dpi::UserSession user_session(dpi::UserSessionTraits(), user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      1000,
      std::nullopt,
      2000
    )
  );

  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    1500, 0, 0);

  if (!res.block)
  {
    std::cerr << TEST_NAME << ": non blocked packet" << std::endl;
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
  dpi::UserSession user_session(dpi::UserSessionTraits(), user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      1000,
      std::nullopt,
      2000
    )
  );

  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    100, 0, 0);

  if (res.block)
  {
    std::cerr << TEST_NAME << ": step1 - expected non blocked packet" << std::endl;
    return false;
  }

  auto used_limits = user_session.get_used_limits();

  if (used_limits.size() != 1 || used_limits.begin()->used_bytes != 100)
  {
    std::cerr << TEST_NAME << ": step2 - unexpected used limits: " <<
      used_limits_to_string(used_limits) <<
      std::endl;
    return false;
  }

  res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    910, 0, 0);

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
  dpi::UserSession user_session(dpi::UserSessionTraits(), user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey("test", std::string()),
      std::nullopt,
      1000,
      std::nullopt,
      2000
    )
  );

  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    100, 0, 0);

  if (res.block)
  {
    std::cerr << TEST_NAME << ": step1 - expected non blocked packet" << std::endl;
    return false;
  }

  auto used_limits = user_session.get_used_limits();

  if (used_limits.size() != 1 || used_limits.begin()->used_bytes != 100)
  {
    std::cerr << TEST_NAME << ": step2 - unexpected used limits: " <<
      used_limits_to_string(used_limits) <<
      std::endl;
    return false;
  }

  user_session.set_limits(limits, used_limits);

  auto last_used_limits = user_session.get_used_limits();

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
    110, 0, 0);

  user_session.set_limits(limits);

  auto last_used_limits2 = user_session.get_used_limits();

  if (last_used_limits2.size() != 1 || last_used_limits2.begin()->used_bytes != 110)
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
  dpi::UserSession user_session(dpi::UserSessionTraits(), user);

  dpi::UserSession::SetLimitArray limits;
  limits.emplace_back(
    dpi::UserSession::SetLimit(
      dpi::SessionKey(),
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
      0
    )
  );
  user_session.set_limits(limits);

  dpi::UserSession::UseLimitResult res = user_session.use_limit(
    dpi::SessionKey("test", std::string()),
    now,
    10, 0, 0);

  if (res.block)
  {
    std::cerr << TEST_NAME << ": blocked packet" << std::endl;
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

  return res ? 0 : -1;
}
