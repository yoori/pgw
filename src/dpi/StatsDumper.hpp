#pragma once

#include <mutex>
#include <fstream>
#include <gears/Time.hpp>
#include <gears/HashTable.hpp>
#include <gears/HashTableAdapters.hpp>

#include "StatCollector.hpp"
#include "UserSessionPacketProcessor.hpp"

namespace dpi
{
  class StatsDumper: public UserSessionPacketProcessor
  {
  public:
    StatsDumper(std::string ch_dump_path);

    virtual PacketProcessingState process_user_session_packet(
      const Gears::Time& time,
      const UserPtr& user,
      uint32_t src_ip,
      uint32_t dst_ip,
      const SessionKey& session_key,
      uint64_t packet_size) override;

    void
    dump();

  protected:
    struct StatKey
    {
      StatKey(
        const Gears::Time& date_val,
        std::string traffic_type_val,
        std::string msisdn_val
        );

      bool
      operator==(const StatKey& right) const;

      unsigned long
      hash() const;

      const Gears::Time date;
      const std::string traffic_type;
      const std::string msisdn;

    protected:
      void calc_hash_();

    protected:
      unsigned long hash_;
    };

    friend std::ostream&
    operator<<(std::ostream& out, const StatKey& dump_value);

    struct StatValue
    {
      StatValue();

      StatValue(int64_t packets_val, int64_t bytes_val);

      StatValue&
      operator+=(const StatValue& right) noexcept;

      int64_t packets;
      int64_t bytes;
    };

    friend std::ostream&
    operator<<(std::ostream& out, const StatValue& dump_value);

    typedef StatCollector<StatKey, StatValue> DetailedStatCollector;

  protected:
    static std::pair<std::string, std::string>
    generate_file_name_(const std::string& prefix);

  protected:
    const std::string ch_dump_path_;

    DetailedStatCollector detailed_stat_collector_;
  };

  typedef std::shared_ptr<StatsDumper> StatsDumperPtr;

  std::ostream&
  operator<<(std::ostream& out, const StatsDumper::StatKey& dump_value);

  std::ostream&
  operator<<(std::ostream& out, const StatsDumper::StatValue& dump_value);
}

namespace dpi
{
  // StatsDumper::StatValue
  inline
  StatsDumper::StatValue::StatValue()
    : packets(0),
      bytes(0)
  {}

  inline
  StatsDumper::StatValue::StatValue(
    int64_t packets_val, int64_t bytes_val)
    : packets(packets_val),
      bytes(bytes_val)
  {}

  inline StatsDumper::StatValue&
  StatsDumper::StatValue::operator+=(
    const StatsDumper::StatValue& right) noexcept
  {
    packets += right.packets;
    bytes += right.bytes;
    return *this;
  }

  // StatsDumper::StatKey
  inline
  StatsDumper::StatKey::StatKey(
    const Gears::Time& date_val,
    std::string traffic_type_val,
    std::string msisdn_val
    )
    : date(date_val),
      traffic_type(std::move(traffic_type_val)),
      msisdn(std::move(msisdn_val)),
      hash_(0)
  {
    calc_hash_();
  }

  inline bool
  StatsDumper::StatKey::operator==(const StatKey& right) const
  {
    return date == right.date &&
      traffic_type == right.traffic_type &&
      msisdn == right.msisdn;
  }

  inline unsigned long
  StatsDumper::StatKey::hash() const
  {
    return hash_;
  }

  inline void
  StatsDumper::StatKey::calc_hash_()
  {
    Gears::Murmur64Hash hasher(hash_);
    hash_add(hasher, date.tv_sec);
    hash_add(hasher, traffic_type);
    hash_add(hasher, msisdn);
  }

  inline std::ostream&
  operator<<(std::ostream& out, const StatsDumper::StatValue& dump_value)
  {
    out << dump_value.packets << "," << dump_value.bytes;
    return out;
  }

  inline std::ostream&
  operator<<(std::ostream& out, const StatsDumper::StatKey& dump_value)
  {
    out << dump_value.date.get_gm_time().format("%F %T") << "," <<
      dump_value.traffic_type << "," <<
      dump_value.msisdn;
    return out;
  }
}
