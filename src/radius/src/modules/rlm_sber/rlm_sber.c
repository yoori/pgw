/**
 * $Id$
 */

RCSID("$Id$")

#define LOG_PREFIX mctx->mi->name

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/module_rlm.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/server/dl_module.h>
#include <freeradius-devel/protocol/freeradius/freeradius.internal.h>
#include <freeradius-devel/unlang/interpret.h>
#include <freeradius-devel/unlang/module.h>

#include "rlm_sber.h"
#include "impl.h"

extern module_rlm_t rlm_sber;

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

static fr_dict_attr_t const *attr_calling_station_id;
static fr_dict_attr_t const *attr_framed_ip_address;
static fr_dict_attr_t const *attr_nas_ip_address;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_imsi;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_rat_type;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_sgsn_mcc_mnc;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_ms_timezone_tz;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_sgsn_address;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_access_network_charging_address;
static fr_dict_attr_t const *attr_vendor_specific_3gpp_charging_id;

extern fr_dict_autoload_t rlm_sber_dict[];
fr_dict_autoload_t rlm_sber_dict[] = {
  { .out = &dict_freeradius, .proto = "freeradius" },
  { .out = &dict_radius, .proto = "radius" },
  { NULL }
};

extern fr_dict_attr_autoload_t rlm_dict_attr[];
fr_dict_attr_autoload_t rlm_dict_attr[] = {
  { .out = &attr_calling_station_id, .name = "Calling-Station-Id", .type = FR_TYPE_STRING, .dict = &dict_radius },
  { .out = &attr_framed_ip_address, .name = "Framed-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
  { .out = &attr_nas_ip_address, .name = "NAS-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_radius },
  {
    .out = &attr_vendor_specific_3gpp_imsi,
    .name = "Vendor-Specific.3GPP.IMSI",
    .type = FR_TYPE_STRING,
    .dict = &dict_radius
  },
  {
    .out = &attr_vendor_specific_3gpp_rat_type,
    .name = "Vendor-Specific.3GPP.RAT-Type",
    .type = FR_TYPE_UINT8,
    .dict = &dict_radius
  },
  {
    .out = &attr_vendor_specific_3gpp_sgsn_mcc_mnc,
    .name = "Vendor-Specific.3GPP.SGSN-MCC-MNC",
    .type = FR_TYPE_STRING,
    .dict = &dict_radius
  },
  {
    .out = &attr_vendor_specific_3gpp_ms_timezone_tz,
    .name = "Vendor-Specific.3GPP.MS-TimeZone.TZ",
    .type = FR_TYPE_UINT8,
    .dict = &dict_radius
  },
  {
    .out = &attr_vendor_specific_3gpp_sgsn_address,
    .name = "Vendor-Specific.3GPP.SGSN-Address",
    .type = FR_TYPE_IPV4_ADDR,
    .dict = &dict_radius
  },
  {
    // In the context of RADIUS, CG-Address (also known as 3GPP CG-Address) refers to a RADIUS
    // attribute used to identify the user's CG (Charging Group) address in a 3GPP network.
    // It's a way to specify the IP address of the user's current charging group within the 3GPP
    // network.
    .out = &attr_vendor_specific_3gpp_access_network_charging_address,
    .name = "Vendor-Specific.3GPP.CG-Address",
    .type = FR_TYPE_IPV4_ADDR,
    .dict = &dict_radius
  },
  {
    .out = &attr_vendor_specific_3gpp_charging_id,
    .name = "Vendor-Specific.3GPP.Charging-ID",
    .type = FR_TYPE_UINT32,
    .dict = &dict_radius
  },

  { NULL }
};

typedef struct {
  char const *config_path;
  size_t config_path_len;
} rlm_sber_t;

static const conf_parser_t module_config[] = {
  { FR_CONF_OFFSET("config_path", rlm_sber_t, config_path), .dflt = "config.json" },
  CONF_PARSER_TERMINATOR
};

// processors
static unlang_action_t mod_authenticate(
  rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);

static unlang_action_t mod_authorize(
  rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);

static unlang_action_t mod_any(
  rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);

// processors implementations.
static unlang_action_t mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
  (void)mctx;
  (void)request;
  RETURN_MODULE_OK;
}

static unlang_action_t mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
  (void)mctx;
  (void)request;
  RETURN_MODULE_OK;
}

static unlang_action_t mod_any(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
  //fr_pair_list_t *list;

  fr_pair_t *attr_called_station_vp;
  fr_pair_t *attr_framed_ip_address_vp;
  fr_pair_t *attr_nas_ip_address_vp;
  fr_pair_t *attr_imsi_vp;
  fr_pair_t *attr_rat_type_vp;
  fr_pair_t *attr_sgsn_mcc_mnc_vp;
  fr_pair_t *attr_ms_timezone_tz_vp;
  fr_pair_t *attr_sgsn_address_vp;
  fr_pair_t *attr_access_network_charging_address_vp;
  fr_pair_t *attr_charging_id_vp;
  bool res;
  (void)mctx;

  attr_called_station_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_calling_station_id);
  attr_framed_ip_address_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_framed_ip_address);
  attr_nas_ip_address_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_nas_ip_address);
  attr_imsi_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_imsi);
  attr_rat_type_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_rat_type);
  attr_sgsn_mcc_mnc_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_sgsn_mcc_mnc);
  attr_ms_timezone_tz_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_ms_timezone_tz);
  attr_sgsn_address_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_sgsn_address);
  attr_access_network_charging_address_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_access_network_charging_address);
  attr_charging_id_vp = fr_pair_find_by_da_nested(
    &request->request_pairs, NULL, attr_vendor_specific_3gpp_charging_id);

  res = tel_gateway_process_request(
    attr_called_station_vp ? attr_called_station_vp->vp_strvalue : 0,
    attr_called_station_vp ? attr_called_station_vp->vp_length : 0,
    attr_framed_ip_address_vp ? *(uint32_t const*)&attr_framed_ip_address_vp->vp_ipv4addr : 0,
    attr_nas_ip_address_vp ? *(uint32_t const*)&attr_nas_ip_address_vp->vp_ipv4addr : 0,
    attr_imsi_vp ? attr_imsi_vp->vp_strvalue : 0,
    attr_rat_type_vp ? attr_rat_type_vp->vp_int8 : 0,
    attr_sgsn_mcc_mnc_vp ? attr_sgsn_mcc_mnc_vp->vp_strvalue : 0,
    attr_ms_timezone_tz_vp ? attr_ms_timezone_tz_vp->vp_uint8 : 0,
    attr_sgsn_address_vp ? *(uint32_t const*)&attr_sgsn_address_vp->vp_ipv4addr : 0,
    attr_access_network_charging_address_vp ?
      *(uint32_t const*)&attr_access_network_charging_address_vp->vp_ipv4addr : 0,
    attr_charging_id_vp ?
      *(uint32_t const*)&attr_charging_id_vp->vp_uint32 : 0
  );

  if (res)
  {
    RETURN_MODULE_OK;
  }
  else
  {
    RETURN_MODULE_REJECT;
  }
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
  rlm_sber_t *inst = talloc_get_type_abort(mctx->mi->data, rlm_sber_t);
  inst->config_path_len = talloc_array_length(inst->config_path) - 1;
  tel_gateway_initialize(inst->config_path, inst->config_path_len);
  return 0;
}

static int mod_load(void)
{
  if (fr_dict_autoload(rlm_sber_dict) < 0)
  {
    return -1;
  }

  if (fr_dict_attr_autoload(rlm_dict_attr) < 0)
  {
    fr_dict_autofree(rlm_sber_dict);
    return -1;
  }

  tel_gateway_load();
  return 0;
}

static void mod_unload(void)
{
  tel_gateway_unload();
}

module_rlm_t rlm_sber = {
  .common = {
    .magic		= MODULE_MAGIC_INIT,
    .name		= "sber",
    .inst_size	= sizeof(rlm_sber_t),
    .config		= module_config,
    .onload		= mod_load,
    .unload		= mod_unload,
    .instantiate	= mod_instantiate,
  },
  .method_group = {
    .bindings = (module_method_binding_t[]){
      { .section = SECTION_NAME("authenticate", CF_IDENT_ANY), .method = mod_authenticate },
      { .section = SECTION_NAME("recv", "Access-Request"), .method = mod_authorize },
      { .section = SECTION_NAME(CF_IDENT_ANY, CF_IDENT_ANY), .method = mod_any },
      MODULE_BINDING_TERMINATOR
    }
  }
};
