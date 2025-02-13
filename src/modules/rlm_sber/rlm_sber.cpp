/**
 * $Id$
 */
#include <include/build.h>

//RCSID("$Id$")

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

extern "C" module_rlm_t rlm_sber;

static const conf_parser_t module_config[] = {
  CONF_PARSER_TERMINATOR
};

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_radius;

extern "C" fr_dict_autoload_t rlm_sber_dict[];
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
  printf("MODULE SBER AUTHENTICATE");
  fflush(stdout);
  RETURN_MODULE_OK;
}

static unlang_action_t mod_authorize(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
  (void)mctx;
  (void)request;
  printf("MODULE SBER AUTHORIZE");
  fflush(stdout);
  RETURN_MODULE_OK;
  //RETURN_MODULE_UPDATED;
}

static unlang_action_t mod_any(rlm_rcode_t *p_result, module_ctx_t const *mctx, request_t *request)
{
  (void)mctx;
  (void)request;
  printf("MODULE SBER ANY");
  fflush(stdout);
  RETURN_MODULE_OK; // RETURN_MODULE_OK;
}

static int mod_instantiate(module_inst_ctx_t const *mctx)
{
  (void)mctx;
  printf("MODULE SBER INSTANTIATE");
  return 0;
}

static int mod_load(void)
{
  printf("MODULE SBER LOADED");
  return 0;
}

static void mod_unload(void)
{
  printf("MODULE SBER UNLOAD");
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
