#pragma once

#include <gears/Exception.hpp>

#include <dpi/UserStorage.hpp>
#include <dpi/UserSessionStorage.hpp>
#include <dpi/Logger.hpp>

#include <dpi/DiameterSession.hpp>
#include <dpi/PccConfigProvider.hpp>

namespace dpi
{
  class Manager
  {
  public:
    DECLARE_EXCEPTION(Invalid, Gears::DescriptiveException);

    enum class AcctStatusType: int
    {
      START = 1,
      STOP = 2,
      UPDATE = 3
    };

  public:
    Manager(
      dpi::UserStoragePtr user_storage,
      dpi::UserSessionStoragePtr user_session_storage,
      dpi::DiameterSessionPtr gx_diameter_session,
      dpi::DiameterSessionPtr gy_diameter_session,
      dpi::PccConfigProviderPtr pcc_config_provider);

    void
    load_config(std::string_view config_path);

    bool
    process_request(
      AcctStatusType acct_status_type,
      const UserSessionTraits& user_session_traits);

    void
    abort_session(
      const std::string& session_id,
      bool terminate_radius,
      bool terminate_gx,
      bool terminate_gy);

    void
    abort_session(
      dpi::UserSession& user_session,
      bool terminate_radius,
      bool terminate_gx,
      bool terminate_gy);

    void
    update_session(const std::string& session_id);

    void
    update_session(dpi::UserSession& user_session);

    dpi::LoggerPtr logger() const;

  private:
    bool
    init_gx_gy_session_(
      const dpi::UserSessionPtr& user_session,
      const dpi::UserSessionTraits& user_session_traits,
      bool init);

    void
    fill_gx_gy_stats_(
      dpi::DiameterSession::GxUpdateRequest& gx_request,
      dpi::DiameterSession::GyRequest& gy_request,
      const dpi::UserSession& user_session);

    std::string
    get_session_suffix_(const std::string& gx_session_id);

    template<typename GxResponseType>
    void
    fill_gy_request_(
      DiameterSession::GyRequest& gy_request,
      UserSession& user_session,
      const UserSessionTraits& user_session_traits,
      const GxResponseType& response,
      const dpi::ConstPccConfigPtr& pcc_config);

    void
    fill_limits_by_gy_response_(
      UserSession& user_session,
      const DiameterSession::GyResponse& gy_response,
      const dpi::ConstPccConfigPtr& pcc_config);

  private:
    const unsigned long GX_APPLICATION_ID_ = 16777238;
    const unsigned long GY_APPLICATION_ID_ = 4;
    dpi::LoggerPtr logger_;
    dpi::UserStoragePtr user_storage_;
    dpi::UserSessionStoragePtr user_session_storage_;
    std::string config_path_;
    std::string diameter_url_;
    dpi::DiameterSessionPtr gx_diameter_session_;
    dpi::DiameterSessionPtr gy_diameter_session_;
    dpi::PccConfigProviderPtr pcc_config_provider_;
  };

  using ManagerPtr = std::shared_ptr<Manager>;
}

namespace dpi
{
  inline LoggerPtr
  Manager::logger() const
  {
    return logger_;
  }
}
