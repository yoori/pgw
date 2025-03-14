#include "DPIUtils.hpp"

char const *
ndpi_cfg_error2string(ndpi_cfg_error const err)
{
  switch (err)
  {
  case NDPI_CFG_INVALID_CONTEXT:
    return "Invalid context";
  case NDPI_CFG_NOT_FOUND:
    return "Configuration not found";
  case NDPI_CFG_INVALID_PARAM:
    return "Invalid configuration parameter";
  case NDPI_CFG_CONTEXT_ALREADY_INITIALIZED:
    return "Configuration context already initialized";
  case NDPI_CFG_CALLBACK_ERROR:
    return "Configuration callback error";
  case NDPI_CFG_OK:
    return "Success";
  }

  return "Unknown";
}
