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

static const conf_parser_t module_config[] = {
  CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern fr_dict_autoload_t rlm_sber_dict[];
fr_dict_autoload_t rlm_sber_dict[] = {
  { .out = &dict_freeradius, .proto = "freeradius" },
  { .out = &dict_radius, .proto = "radius" },
  { NULL }
};


static unlang_action_t mod_authenticate(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);
static unlang_action_t mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);
static unlang_action_t mod_any(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request) CC_HINT(nonnull);


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
  (void)mctx;
  (void)request;
  tel_gateway_process_request();
  RETURN_MODULE_OK;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
  (void)mctx;
  tel_gateway_initialize();
  return 0;
}

static int mod_load(void)
{
  tel_gateway_load();
  return 0;
}

static void mod_unload(void)
{
  tel_gateway_unload();
}

typedef struct {
} rlm_sber_t;

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
