#include "config.h"

#include <epan/packet.h>
#include <epan/stats_tree.h>

#define TOX_PORT 33445

static int proto_tox = -1;
static int hf_tox_pdu_type = -1;
static int hf_tox_dhtpubkey = -1;
static int hf_tox_nonce = -1;
static int hf_tox_crypted = -1;
static int hf_tox_noncetail = -1;

static gint ett_tox = -1;
static int tox_tap = -1;

static const guint8* st_str_packets = "Total Packets";
static const guint8* st_str_packet_types = "tox Packet Types";
static int st_node_packets = -1;
static int st_node_packet_types = -1;

struct ToxTap {
  gint packet_type;
};

static const value_string packettypenames [] = {
  { 0, "DHT Ping" },
  { 1, "DHT Pong" },
  { 2, "Get Nodes" },
  { 4, "Send Nodes" },
  { 24, "Cookie Request" },
  { 25, "Cookie Response" },
  { 26, "Handshake" },
  { 27, "Data" },
  { 33, "Lan discovery" },
  { 128, "Onion 1" },
  { 129, "Onion 2" },
  { 130, "Onion 3" },
  { 131, "Onion Announce" },
  { 132, "Onion Response" },
  { 133, "Onion Data A" },
  { 134, "Onion Data B" },
  { 140, "Onion Reply 1" },
  { 141, "Onion Reply 2" },
  { 142, "Onion Reply 3" },
  { 0, NULL }
};

static void dissect_tox(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset = 0;

  guint8 packet_type = tvb_get_guint8(tvb,0);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOX");
  col_clear(pinfo->cinfo,COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

  if (tree) {
    proto_item *ti = NULL;
    proto_tree *tox_tree = NULL;

    ti = proto_tree_add_item(tree, proto_tox, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti,", Type %s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    tox_tree = proto_item_add_subtree(ti, ett_tox);
    proto_tree_add_item(tox_tree, hf_tox_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    switch (packet_type) {
    case 0:
    case 1:
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 2:
    case 4:
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 24:
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 25:
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 27:
      proto_tree_add_item(tox_tree, hf_tox_noncetail, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 33:
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      break;
    case 128:
    case 129:
    case 130:
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 131:
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    case 133:
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      break;
    case 140:
    case 141:
    case 142:
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      break;
    }
  }

  struct ToxTap *toxinfo = wmem_alloc(wmem_packet_scope(), sizeof(struct ToxTap));
  toxinfo->packet_type = packet_type;
  tap_queue_packet(tox_tap, pinfo, toxinfo);
}

static void tox_stats_tree_init(stats_tree *st) {
  puts("stats init");
  st_node_packets = stats_tree_create_node(st, st_str_packets, 0, TRUE);
  st_node_packet_types = stats_tree_create_pivot(st, st_str_packet_types, st_node_packets);
}

static int tox_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt, const void *p) {
  puts("stating packet");
  struct ToxTap *pi = (struct ToxTap*)p;
  tick_stat_node(st, st_str_packets, 0, FALSE);
  stats_tree_tick_pivot(st, st_node_packet_types, val_to_str(pi->packet_type,packettypenames,"Unknown (0x%02x)"));
  return 1;
}

void proto_register_tox(void) {
  static hf_register_info hf[] = {
    { &hf_tox_pdu_type , { "packet type", "tox.type"     , FT_UINT8, BASE_DEC , VALS(packettypenames), 0x0, NULL, HFILL } },
    { &hf_tox_dhtpubkey, { "DHT Pubkey" , "tox.dhtpubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_nonce    , { "Nonce"      , "tox.nonce"    , FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_crypted  , { "Encrypted"  , "tox.crypted"  , FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_noncetail, { "Nonce-tail" , "tox.noncetail", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } }
  };

  static gint *ett[] = { &ett_tox };
  proto_tox = proto_register_protocol ("Tox Protocol", "Tox", "tox");
  proto_register_field_array(proto_tox, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  tox_tap = register_tap("tox");
  puts("registering stats");
  stats_tree_register("tox","tox","tox/packet types", 0, tox_stats_tree_packet, tox_stats_tree_init,NULL);
}

void proto_reg_handoff_tox(void) {
  static dissector_handle_t tox_handle;

  tox_handle = create_dissector_handle(dissect_tox, proto_tox);
  dissector_add_uint("udp.port",TOX_PORT,tox_handle);
}
