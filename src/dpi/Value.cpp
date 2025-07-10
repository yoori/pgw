#include "Value.hpp"

namespace dpi
{
  namespace
  {
    class ValueAsStringVisitor
    {
    public:
      ValueAsStringVisitor(std::string& result)
        : result_(result)
      {}

      void
      operator()(const std::string& val)
      {
        result_ = val;
      }

      void
      operator()(int64_t val)
      {
        result_ = std::to_string(val);
      }

      void
      operator()(uint64_t val)
      {
        result_ = std::to_string(val);
      }

      void
      operator()(const ByteArrayValue& val)
      {
        result_ = std::string(reinterpret_cast<const char*>(&val[0]), val.size());
      }

    private:
      std::string& result_;
    };
  }

  std::string
  value_as_string(const Value& value)
  {
    std::string res;
    ValueAsStringVisitor visitor(res);
    std::visit(visitor, value);
    return res;
  }
}
