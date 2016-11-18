#include "config.h"

#include <epan/packet.h>
#include <epan/stats_tree.h>
#include <epan/to_str.h>
#include <epan/address.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <sodium/crypto_box.h>
#include <sodium/core.h>

#define TOX_PORT 33445

struct ToxTap {
  gint packet_type;
};
struct keypair {
  uint8_t public[32];
  uint8_t private[32];
};
struct remote_node {
  address ipaddr;
  uint8_t public[32];
};

static int proto_tox = -1;
static int hf_tox_pdu_type = -1;
static int hf_tox_dhtpubkey = -1;
static int hf_tox_nonce = -1;
static int hf_tox_crypted = -1;
static int hf_tox_noncetail = -1;
static int hf_tox_ping_type = -1, hf_tox_ping_id = -1, hf_tox_send_count = -1;
static int hf_tox_module = -1;
static int hf_tox_address_family = -1;
static int hf_tox_node_address4 = -1;
static int hf_tox_node_address6 = -1;
static int hf_tox_node_port = -1;

static gint ett_tox = -1, ett_node = -1;
static int tox_tap = -1;

static const guint8* st_str_packets = "Total Packets";
static const guint8* st_str_packet_types = "tox Packet Types";
static int st_node_packets = -1;
static int st_node_packet_types = -1;

struct keypair *dhtkeys = 0;
int dht_key_count = 0;

struct remote_node *remote_nodes = 0;
int remote_node_count = 0;

static const value_string pingtype [] = { { 0, "Ping" }, { 1, "Pong" }, { 0, NULL } };
static const value_string packettypenames [] = {
  { 0, "DHT Ping" },
  { 1, "DHT Pong" },
  { 2, "Get Nodes" },
  { 4, "Send Nodes" },
  { 16, "Alive" }, // friend_connection.h
  { 17, "Share Relays" }, // friend_connection.h
  { 18, "Friend Requests" }, // friend_connection.h
  { 24, "Cookie Request" }, // Messenger.h
  { 25, "Cookie Response" }, // Messenger.h
  { 26, "Handshake" },
  { 27, "Data" }, // NET_PACKET_CRYPTO_DATA
  { 32, "Friend Request" },
  { 33, "Lan discovery" },
  { 48, "Nickname" }, // Messenger.h
  { 49, "Status Message" }, // Messenger.h
  { 50, "User Status" }, // Messenger.h
  { 51, "Typing" }, // Messenger.h
  { 64, "Message" }, // Messenger.h
  { 65, "Action" }, // Messenger.h
  { 69, "MSI" }, // Messenger.h
  { 80, "file send request" }, // Messenger.h
  { 81, "file control" }, // Messenger.h
  { 82, "file data" }, // Messenger.h
  { 96, "Invite Groupchat" }, // Messenger.h
  { 97, "online" }, // Messenger.h
  { 98, "direct groupchat" }, // Messenger.h
  { 99, "message groupchat" }, // Messenger.h
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
  { 199, "lossy groupchat" },
  { 0, NULL }
};

static const value_string address_families [] = {
  { 0x02, "UDPv4" },
  { 0x0a, "UDPv6" },
  { 0x82, "TCPv4" },
  { 0x8a, "TCPv6" },
  { 0, NULL }
};

void to_hex(char *a, const uint8_t *p, int size) {
  char buffer[3];
  int i;
  for (i=0; i<size; i++) {
    int x = snprintf(buffer,3,"%02x",p[i]);
    a[i*2] = buffer[0];
    a[i*2+1] = buffer[1];
  }
  a[size*2] = 0;
}
static struct remote_node *find_node(const address *addr) {
  int i;
  for (i=0; i<remote_node_count; i++) {
    if (addresses_equal(&remote_nodes[i].ipaddr,addr)) {
      //gchar str[64];
      //address_to_str_buf(addr,str,63);
      //printf("found node %s in slot %d\n",str,i);
      return &remote_nodes[i];
    }
  }
  return 0;
}
static tvbuff_t *try_decrypt(packet_info *pinfo, tvbuff_t *tvb, gint pubkeyoffset, gint nonceoffset, gint cipheroffset) {
  int i;
  const guint8 *ciphertext = tvb_get_ptr(tvb,cipheroffset,-1);
  gint ciphersize = tvb_captured_length_remaining(tvb,cipheroffset);

  const guint8 *nonce = tvb_get_ptr(tvb,nonceoffset,24);

  for (i=0; i<dht_key_count; i++) {
    if (tvb_memeql(tvb,pubkeyoffset,dhtkeys[i].public,32) == 0) {
      struct remote_node *remote = find_node(&pinfo->dst);
      if (!remote) break;

      uint8_t *plaintext = g_malloc(ciphersize - crypto_box_MACBYTES);

      if (crypto_box_open_easy(plaintext, ciphertext, ciphersize, nonce, remote->public, dhtkeys[i].private) == 0) {
        tvbuff_t *next_tvb = tvb_new_child_real_data(tvb,plaintext,ciphersize - crypto_box_MACBYTES,ciphersize - crypto_box_MACBYTES);
        tvb_set_free_cb(next_tvb,g_free);
        add_new_data_source(pinfo,next_tvb,"Decrypted Data");
        return next_tvb;
      } else {
        g_free(plaintext);
      }
    }
  }
  const guint8 *srcpublic = tvb_get_ptr(tvb, pubkeyoffset, crypto_box_PUBLICKEYBYTES);

  //puts("source pubkey not found in toxcore dump, trying each dht key as dest");
  for (i=0; i<dht_key_count; i++) {
    uint8_t *plaintext = g_malloc(ciphersize - crypto_box_MACBYTES);
    if (crypto_box_open_easy(plaintext, ciphertext, ciphersize, nonce, srcpublic, dhtkeys[i].private) == 0) {
      tvbuff_t *next_tvb = tvb_new_child_real_data(tvb,plaintext,ciphersize - crypto_box_MACBYTES,ciphersize - crypto_box_MACBYTES);
      tvb_set_free_cb(next_tvb,g_free);
      add_new_data_source(pinfo,next_tvb,"Decrypted Data");
      return next_tvb;
    } else {
      g_free(plaintext);
    }
  }
  printf("unable to decrypt packet %d\n",pinfo->num);
  return 0;
}

/**
  * saves the dht public key of the address in src
  **/
void log_pubkey_raw(packet_info *pinfo, tvbuff_t *tvb, const address *src, int offset) {
  guchar str[64];

  struct remote_node *old_entry = find_node(src);
  if (old_entry) return;

  address_to_str_buf(src,str,63);

  remote_node_count++;
  remote_nodes = realloc(remote_nodes,sizeof(struct remote_node) * remote_node_count);
  copy_address(&remote_nodes[remote_node_count-1].ipaddr,src);
  // FIXME
  int i;
  for (i=0; i<32; i++) {
    remote_nodes[remote_node_count-1].public[i] = tvb_get_guint8(tvb,offset+i);
  }
  printf("added %s to slot %d\n",str,remote_node_count-1);

}
void log_pubkey(packet_info *pinfo, tvbuff_t *tvb, const address *src, guint8 type) {
  guchar str[64];
  address_to_str_buf(src,str,63);
  struct remote_node *old_entry = find_node(src);
  if (old_entry) return;
  int offset = -1;
  switch (type) {
  case 0:
  case 1:
  case 2:
  case 4:
  case 33:
  case 131:
    offset = 1;
    break;
  case 27:
  case 140:
    return;
  }
  if (offset > 0) {
    log_pubkey_raw(pinfo, tvb, src, offset);
  } else {
    printf("cant save %d %s, type %d has no set offset\n", pinfo->num, str, type);
  }
}

static int dissect_tox(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *something) {
  gint offset = 0;
  tvbuff_t *plaintext = 0;

  guint8 packet_type = tvb_get_guint8(tvb,0);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TOX");
  col_clear(pinfo->cinfo,COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

  log_pubkey(pinfo, tvb,&pinfo->src,packet_type);

  if (tree) {
    //printf("%d: deep decoding type %d\n",pinfo->fd->num,packet_type);
    proto_item *ti = NULL;
    proto_tree *tox_tree = NULL;

    ti = proto_tree_add_item(tree, proto_tox, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti,", Type %s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));

    tox_tree = proto_item_add_subtree(ti, ett_tox);

    proto_tree_add_item(tox_tree, hf_tox_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    switch (packet_type) {
    case 0:
    case 1: {
      gint pubkeyoffset = offset;
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      gint nonceoffset = offset;
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      gint cipheroffset = offset;
      plaintext = try_decrypt(pinfo, tvb,pubkeyoffset,nonceoffset,cipheroffset);
      if (plaintext) {
        proto_tree_add_item(tox_tree, hf_tox_ping_type, plaintext, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tox_tree, hf_tox_ping_id, plaintext, 1, 8, ENC_BIG_ENDIAN);
      } else {
        proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      }
      break;
    }
    case 2:
    case 4: {
      gint pubkeyoffset = offset;
      proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, tvb, offset, 32, ENC_BIG_ENDIAN);
      offset += 32;
      gint nonceoffset = offset;
      proto_tree_add_item(tox_tree, hf_tox_nonce, tvb, offset, 24, ENC_BIG_ENDIAN);
      offset += 24;
      gint cipheroffset = offset;
      plaintext = try_decrypt(pinfo, tvb,pubkeyoffset,nonceoffset,cipheroffset);
      if (plaintext) {
        if (packet_type == 2) {
          proto_tree_add_item(tox_tree, hf_tox_dhtpubkey, plaintext, 0, 32, ENC_BIG_ENDIAN);
        } else {
          guint8 node_count = tvb_get_guint8(plaintext, 0);
          proto_tree_add_item(tox_tree, hf_tox_send_count, plaintext, 0, 1, ENC_BIG_ENDIAN);

          int offset = 1;
          for (int i=0; i<node_count; i++) {
            guint8 addr_family = tvb_get_guint8(plaintext, offset);
            bool ipv4 = true;
            int length = -1;
            if ((addr_family == 0x02) || (addr_family == 0x82)) {
              ipv4 = true;
              length = 39;
            } else if ((addr_family == 0x0a) || (addr_family == 0x8a)) {
              ipv4 = false;
              length = 51;
            } else break;

            proto_item *node_item;
            proto_tree *node_tree = proto_tree_add_subtree(tox_tree, plaintext, offset, length, ett_node, &node_item, "Node");
            proto_tree_add_item(node_tree, hf_tox_address_family, plaintext, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            guchar *buffer = NULL;
            address addr;

            if (ipv4) {
              guint32 address4 = tvb_get_ipv4(plaintext, offset);
              set_address(&addr, AT_IPv4, 4, &address4);
              buffer = address_to_str(wmem_packet_scope(), &addr);
              proto_tree_add_ipv4(node_tree, hf_tox_node_address4, plaintext, offset, 4, address4);
              offset += 4;
            } else {
              struct e_in6_addr address6;
              tvb_get_ipv6(plaintext, offset, &address6);
              set_address(&addr, AT_IPv6, sizeof(struct e_in6_addr), &address6);
              buffer = address_to_str(wmem_packet_scope(), &addr);
              proto_tree_add_ipv6(node_tree, hf_tox_node_address6, plaintext, offset, 16, &address6);
              offset += 16;
            }

            guint16 port = tvb_get_guint16(plaintext, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(node_tree, hf_tox_node_port, plaintext, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_item_set_text(node_item, "[%s]:%d", buffer, port);


            log_pubkey_raw(pinfo, plaintext, &addr, offset);
            proto_tree_add_item(node_tree, hf_tox_dhtpubkey, plaintext, offset, 32, ENC_BIG_ENDIAN);
            offset += 32;
          }
        }
      } else {
        proto_tree_add_item(tox_tree, hf_tox_crypted, tvb, offset, -1, ENC_BIG_ENDIAN);
      }
      break;
    }
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
    case 32:
      offset += 4;
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

  return tvb_captured_length(tvb);
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
void hex_string_to_bin(const char *hex_string, uint8_t *ret)
{
    // byte is represented by exactly 2 hex digits, so lenth of binary string
    // is half of that of the hex one. only hex string with even length
    // valid. the more proper implementation would be to check if strlen(hex_string)
    // is odd and return error code if it is. we assume strlen is even. if it's not
    // then the last byte just won't be written in 'ret'.
    size_t i, len = strlen(hex_string) / 2;
    const char *pos = hex_string;

    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &ret[i]);
}

void process_keys(FILE *input) {
  int ret;
  char name[10],public[65],private[65];
  while (!feof(input)) {
    fscanf(input,"%9s %64s %64s\n",&name,&public,&private);
    printf("name:%s pub:%s priv:%s\n",name,public,private);
    if (strcmp("DHT",name) == 0) {
      dht_key_count++;
      dhtkeys = realloc(dhtkeys,sizeof(struct keypair) * dht_key_count);
      hex_string_to_bin(public,dhtkeys[dht_key_count-1].public);
      hex_string_to_bin(private,dhtkeys[dht_key_count-1].private);
    }
  }
}

void proto_register_tox(void) {
  if (sodium_init() == -1) {
    fprintf(stderr, "fatal error loading sodium\n");
    return;
  }
  char *value = getenv("TOX_LOG_KEYS");
  if (value) {
    printf("loading tox private keys from %s\n",value);
    FILE *keys = fopen(value,"r");
    if (keys) {
      process_keys(keys);
      fclose(keys);
    }
  }
  static hf_register_info hf[] = {
    { &hf_tox_pdu_type , { "Packet Type", "tox.type"     , FT_UINT8, BASE_DEC , VALS(packettypenames), 0x0, NULL, HFILL } },
    { &hf_tox_dhtpubkey, { "DHT Pubkey" , "tox.dhtpubkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_nonce    , { "Nonce"      , "tox.nonce"    , FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_crypted  , { "Ciphertext"  , "tox.ciphertext",FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_noncetail, { "Nonce-tail" , "tox.noncetail", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_ping_type, { "Ping Type"  , "tox.pingtype" , FT_UINT8, BASE_DEC, VALS(pingtype), 0x0, NULL, HFILL } },
    { &hf_tox_ping_id  , { "Ping ID"    , "tox.pingid"   , FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_send_count,{ "Node Count" , "tox.nodecount", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_module   , { "Module"     , "tox.module"   , FT_STRING,BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_address_family, { "Address Family", "tox.addrfamily", FT_UINT8, BASE_DEC, VALS(address_families), 0x0, NULL, HFILL } },
    { &hf_tox_node_address4, { "Node Address", "tox.node_address", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_node_address6, { "Node Address", "tox.node_address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_tox_node_port, { "Node Port", "tox.node_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } }
  };

  static gint *ett[] = { &ett_tox, &ett_node };
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
