/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from /home/clever/x/wireshark-2.2.0/tools/make-dissector-reg.py.
 */

#include "config.h"

#include <gmodule.h>
#include <epan/proto.h>

#include "moduleinfo.h"

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF void plugin_register (void);
WS_DLL_PUBLIC_DEF const gchar version[] = VERSION;
WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const gchar plugin_release[] = "2.6";

extern void proto_register_tox(void);
extern void proto_reg_handoff_tox(void);

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_DEF void
plugin_register (void)
{
  static proto_plugin plugin_foo;
  plugin_foo.register_protoinfo = proto_register_tox;
  plugin_foo.register_handoff = proto_reg_handoff_tox;
  proto_register_plugin(&plugin_foo);
}


WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

WS_DLL_PUBLIC_DEF void
plugin_reg_handoff(void)
{
    proto_reg_handoff_tox();
}

#endif
