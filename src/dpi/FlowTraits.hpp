#pragma once

#include <optional>
#include <cstdint>

namespace dpi
{
  struct FlowTraits
  {
    //u_int16_t proto = 0;
    FlowTraits() {};

    FlowTraits(
      uint32_t src_ip_val,
      const std::optional<uint32_t>& src_port_val,
      uint32_t dst_ip_val,
      const std::optional<uint32_t>& dst_port_val,
      const std::string& protocol_val);

    uint32_t src_ip = 0;
    std::optional<uint32_t> src_port; // defined only for protocols with ports
    uint32_t dst_ip = 0;
    std::optional<uint32_t> dst_port;
    std::string protocol;
  };
}

namespace dpi
{
  inline
  FlowTraits::FlowTraits(
    uint32_t src_ip_val,
    const std::optional<uint32_t>& src_port_val,
    uint32_t dst_ip_val,
    const std::optional<uint32_t>& dst_port_val,
    const std::string& protocol_val)
    : src_ip(src_ip_val),
      src_port(src_port_val),
      dst_ip(dst_ip_val),
      dst_port(dst_port_val),
      protocol(protocol_val)
  {};
}
