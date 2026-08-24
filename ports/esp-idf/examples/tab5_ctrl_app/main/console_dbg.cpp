// デバッグ用コンソール(T5a、docs/design/p4-thread-controller.md §13.1)。
//
// USB-Serial-JTAG の esp_console REPL に、UI と同じ操作キュー(sm_app_post_op)へ
// 投げるコマンドを載せる。**sm_ctrl_* / lv_* は呼ばない**(単線契約は不変。
// pump から見れば GUI のタップと区別がつかない = 実機で GUI と同一経路の検証になる)。
// 出力は 1 行 1 レコード + OK/ERR 終端(スクリプトから grep できる安定書式)。

#include "console_dbg.hpp"

#include "app_state.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "esp_console.h"
#include "lwip/sockets.h"
#include "esp_log.h"

namespace {

uint64_t parse_hex(const char *s) { return strtoull(s, nullptr, 16); }

int cmd_nodes(int, char **) {
  sm_ui_snapshot_t snap;
  sm_app_snapshot_get(&snap);
  printf("NODES %u\n", (unsigned)snap.node_count);
  for (size_t i = 0; i < snap.node_count && i < SM_UI_MAX_NODES; ++i) {
    const sm_ui_node_t &n = snap.nodes[i];
    printf("NODE %016llx kind=%u onoff=%d aq=%u addr=%s note=\"%s\"\n",
           (unsigned long long)n.node_id, n.kind, (int)n.onoff, n.aq, n.addr, n.note);
  }
  printf("OK\n");
  return 0;
}

int cmd_status(int, char **) {
  sm_ui_snapshot_t snap;
  sm_app_snapshot_get(&snap);
  printf("STATUS thread_role=%d wifi_state=%u wifi_ip4=%s wifi_ll=%s wifi_gua_ok=%d ble=%u "
         "pair_state=%u pair_phase=%u ble_stage=%u nodes=%u\n",
         snap.role, snap.wifi_state, snap.wifi_ip4[0] ? snap.wifi_ip4 : "-",
         snap.wifi_ll[0] ? snap.wifi_ll : "-", 0, snap.ble_host, snap.pair_state, snap.pair_phase,
         snap.ble_stage, (unsigned)snap.node_count);
  printf("LAST \"%s\"\n", snap.status);
  printf("OK\n");
  return 0;
}

int cmd_toggle(int argc, char **argv) {
  if (argc < 2) {
    printf("ERR usage: toggle <node_hex>\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_TOGGLE;
  op.node_id = parse_hex(argv[1]);
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_read(int argc, char **argv) {
  if (argc < 2) {
    printf("ERR usage: read <node_hex>\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_READ_ONOFF;
  op.node_id = parse_hex(argv[1]);
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_pairble(int argc, char **argv) {
  // pairble <disc> <node_hex> [wifi|thread] [passcode]
  if (argc < 3) {
    printf("ERR usage: pairble <disc> <node_hex> [wifi|thread] [passcode]\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_PAIR_BLE;
  op.discriminator = (uint16_t)atoi(argv[1]);
  op.node_id = parse_hex(argv[2]);
  op.via = (argc >= 4 && strcmp(argv[3], "thread") == 0) ? SM_UI_VIA_BLE_THREAD : SM_UI_VIA_BLE_WIFI;
  op.passcode = (argc >= 5) ? (uint32_t)strtoul(argv[4], nullptr, 10) : 20202021u;
  if (op.node_id == 0) {
    printf("ERR node id must be non-zero\n");
    return 1;
  }
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

int cmd_pair(int argc, char **argv) {
  // pair <ipv6> <node_hex> [thread|wifi] [passcode]
  if (argc < 3) {
    printf("ERR usage: pair <ipv6> <node_hex> [thread|wifi] [passcode]\n");
    return 1;
  }
  sm_ui_op_t op = {};
  op.kind = SM_UI_OP_PAIR;
  snprintf(op.ipv6, sizeof(op.ipv6), "%s", argv[1]);
  op.node_id = parse_hex(argv[2]);
  op.via = (argc >= 4 && strcmp(argv[3], "wifi") == 0) ? SM_UI_VIA_WIFI : SM_UI_VIA_THREAD;
  op.passcode = (argc >= 5) ? (uint32_t)strtoul(argv[4], nullptr, 10) : 20202021u;
  if (op.node_id == 0) {
    printf("ERR node id must be non-zero\n");
    return 1;
  }
  printf(sm_app_post_op(&op) ? "OK queued\n" : "ERR queue full\n");
  return 0;
}

// RX 切り分け実験: 指定ポートに bind(+224.0.0.251 join)して数秒間の受信を数える。
// 使い方: udptest <port> <secs>。PC から unicast / multicast を打って比較する。
int cmd_udptest(int argc, char **argv) {
  if (argc < 3) {
    printf("ERR usage: udptest <port> <secs>\n");
    return 1;
  }
  uint16_t port = (uint16_t)atoi(argv[1]);
  int secs = atoi(argv[2]);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    printf("ERR socket\n");
    return 1;
  }
  int on = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  struct sockaddr_in a = {};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  if (bind(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
    printf("ERR bind errno=%d\n", errno);
    close(fd);
    return 1;
  }
  struct ip_mreq m = {};
  m.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
  m.imr_interface.s_addr = htonl(INADDR_ANY);
  int jr = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &m, sizeof(m));
  printf("LISTEN port=%u join_rc=%d for %ds\n", port, jr, secs);
  uint64_t until = (uint64_t)secs * 1000;
  uint32_t got = 0;
  for (uint64_t t = 0; t < until; t += 200) {
    struct timeval tv = {0, 200000};
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(fd, &rf);
    if (select(fd + 1, &rf, nullptr, nullptr, &tv) > 0) {
      uint8_t buf[1500];
      struct sockaddr_in src;
      socklen_t sl = sizeof(src);
      int n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&src, &sl);
      if (n > 0) {
        char ip[20];
        inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
        printf("RX %d B from %s:%u\n", n, ip, ntohs(src.sin_port));
        got++;
      }
    }
  }
  close(fd);
  printf("DONE rx=%u\nOK\n", (unsigned)got);
  return 0;
}

void reg(const char *name, const char *help, esp_console_cmd_func_t fn) {
  const esp_console_cmd_t c = {
      .command = name,
      .help = help,
      .hint = nullptr,
      .func = fn,
      .argtable = nullptr,
      .func_w_context = nullptr,
      .context = nullptr,
  };
  ESP_ERROR_CHECK(esp_console_cmd_register(&c));
}

} // namespace

void sm_console_start() {
  esp_console_repl_t *repl = nullptr;
  esp_console_repl_config_t repl_cfg = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
  repl_cfg.prompt = "tab5>";
  repl_cfg.max_cmdline_length = 128;
  esp_console_dev_usb_serial_jtag_config_t hw = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
  if (esp_console_new_repl_usb_serial_jtag(&hw, &repl_cfg, &repl) != ESP_OK) {
    ESP_LOGW("con", "console repl init failed (continuing without it)");
    return;
  }
  reg("nodes", "list nodes", cmd_nodes);
  reg("status", "controller status", cmd_status);
  reg("toggle", "toggle <node_hex>", cmd_toggle);
  reg("read", "read <node_hex>", cmd_read);
  reg("pairble", "pairble <disc> <node_hex> [wifi|thread] [passcode]", cmd_pairble);
  reg("pair", "pair <ipv6> <node_hex> [thread|wifi] [passcode]", cmd_pair);
  reg("udptest", "udptest <port> <secs>", cmd_udptest);
  ESP_ERROR_CHECK(esp_console_start_repl(repl));
  ESP_LOGI("con", "debug console ready (nodes/status/toggle/read/pair/pairble)");
}
