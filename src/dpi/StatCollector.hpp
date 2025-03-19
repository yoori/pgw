#pragma once

#include <mutex>
#include <fstream>
#include <gears/Time.hpp>
#include <gears/HashTable.hpp>
#include <gears/HashTableAdapters.hpp>

#include "UserSessionPacketProcessor.hpp"

namespace dpi
{
  template<typename KeyType, typename ValueType>
  class StatCollector
  {
  public:
    DECLARE_EXCEPTION(Exception, Gears::DescriptiveException);

    StatCollector();

    bool
    dump(const std::string& file_path);

    void
    add_record(const KeyType& key, const ValueType& value) noexcept;

  protected:
    typedef Gears::HashTable<KeyType, ValueType> Container;

  protected:
    mutable std::mutex cont_lock_;
    Container cont_;
  };
}

namespace dpi
{
  template<typename KeyType, typename ValueType>
  StatCollector<KeyType, ValueType>::StatCollector()
  {}

  template<typename KeyType, typename ValueType>
  void
  StatCollector<KeyType, ValueType>::add_record(const KeyType& key, const ValueType& value) noexcept
  {
    std::unique_lock<std::mutex> guard(cont_lock_);
    cont_[key] += value;
  }

  template<typename KeyType, typename ValueType>
  bool
  StatCollector<KeyType, ValueType>::dump(const std::string& file_path)
  {
    static const char* FUN = "StatCollector<>::dump()";

    Container cont;

    {
      std::unique_lock<std::mutex> guard(cont_lock_);
      cont_.swap(cont);
    }

    if(!cont.empty())
    {
      std::ofstream file(file_path);
      if(!file.is_open())
        {
          Gears::ErrorStream ostr;
          ostr << FUN << ": can't open file '" << file_path << "'";
          throw Exception(ostr.str());
        }

      for(auto it = cont.begin(); it != cont.end(); ++it)
      {
        file << it->first << "," << it->second << std::endl;
      }

      if(file.fail() || file.bad())
        {
          Gears::ErrorStream ostr;
          ostr << FUN << ": can't save file '" << file_path << "'";
          throw Exception(ostr.str());
        }

      file.close();

      return true;
    }

    return false;
  }
}
