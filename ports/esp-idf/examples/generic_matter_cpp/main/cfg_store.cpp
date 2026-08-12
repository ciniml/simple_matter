// 設定 blob の NVS 格納 + esp_console(USB-Serial-JTAG)コマンド。cfg_store.hpp 参照。
//
//   cfg-comp <hex>   composition TLV を保存(§9.1)
//   cfg-bind <hex>   binding TLV を保存(§9.2)
//   cfg-show         保存済み blob を hex で表示 + binding をデコードして表示
//   cfg-clear        両方を消す(次回起動は既定構成)
//   restart          再起動(設定を反映)
//
// hex は scripts/smgen-tlv.py が出力するものをそのまま貼る。

#include "cfg_store.hpp"

#include "bind_tlv.hpp"

#include <cstdio>
#include <cstring>

#include "esp_console.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs.h"

namespace smgen {
namespace {

const char *TAG = "smgen_cfg";

// 1 文字の hex → 0..15(不正は -1)。
int hex_val(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

// hex 文字列 → バイト列(空白は無視)。戻り値 = バイト数、負値 = 不正。
int hex_decode(const char *s, uint8_t *out, size_t cap) {
  size_t n = 0;
  int hi = -1;
  for (const char *p = s; *p; ++p) {
    if (*p == ' ' || *p == '\t' || *p == '_' || *p == ':') {
      continue;
    }
    const int v = hex_val(*p);
    if (v < 0) {
      return -1;
    }
    if (hi < 0) {
      hi = v;
    } else {
      if (n >= cap) {
        return -2;
      }
      out[n++] = (uint8_t)((hi << 4) | v);
      hi = -1;
    }
  }
  return (hi >= 0) ? -1 : (int)n;
}

void print_hex(const uint8_t *b, size_t n) {
  for (size_t i = 0; i < n; i++) {
    printf("%02x", b[i]);
  }
  printf("\n");
}

// `cfg-comp` / `cfg-bind` の共通処理。
int store_blob_cmd(const char *key, int argc, char **argv) {
  if (argc != 2) {
    printf("usage: %s <hex>  (scripts/smgen-tlv.py の出力)\n", argv[0]);
    return 1;
  }
  static uint8_t buf[kMaxBlob];
  const int n = hex_decode(argv[1], buf, sizeof(buf));
  if (n < 0) {
    printf("error: invalid hex (%s)\n", n == -2 ? "too long" : "bad digit");
    return 1;
  }
  if (n == 0) {
    printf("error: empty blob (use cfg-clear)\n");
    return 1;
  }
  if (strcmp(key, "bind") == 0) {
    // 保存前にパースして弾く(壊れた表で起動しないため)。
    BindingTable t;
    const int rc = parse_bindings(buf, (size_t)n, t);
    if (rc != BIND_OK) {
      printf("error: binding TLV rejected (rc=%d)\n", rc);
      return 1;
    }
    printf("parsed %u binding(s)\n", (unsigned)t.n);
  }
  if (!cfg_save(key, buf, (size_t)n)) {
    printf("error: NVS write failed\n");
    return 1;
  }
  printf("saved %s: %d bytes (restart to apply)\n", key, n);
  return 0;
}

int cmd_cfg_comp(int argc, char **argv) { return store_blob_cmd("comp", argc, argv); }
int cmd_cfg_bind(int argc, char **argv) { return store_blob_cmd("bind", argc, argv); }

int cmd_cfg_show(int, char **) {
  static uint8_t buf[kMaxBlob];
  size_t n = cfg_load("comp", buf, sizeof(buf));
  printf("comp: %u bytes\n", (unsigned)n);
  if (n) {
    print_hex(buf, n);
  } else {
    printf("(unset -> default: EP1 OnOff light)\n");
  }
  n = cfg_load("bind", buf, sizeof(buf));
  printf("bind: %u bytes\n", (unsigned)n);
  if (n) {
    print_hex(buf, n);
    BindingTable t;
    const int rc = parse_bindings(buf, n, t);
    if (rc != BIND_OK) {
      printf("(binding TLV invalid: rc=%d)\n", rc);
    } else {
      for (size_t i = 0; i < t.n; i++) {
        const Binding &b = t.items[i];
        printf("  [%u] ep=%u cluster=0x%04x drv=%s params=", (unsigned)i, b.ep,
               (unsigned)b.cluster, drv_name(b.drv));
        for (size_t k = 0; k < kMaxParams; k++) {
          if (b.has[k]) {
            printf("%u:%llu ", (unsigned)k, (unsigned long long)b.p[k]);
          }
        }
        printf("\n");
      }
    }
  } else {
    printf("(unset -> default: gpio_out on the Kconfig pin)\n");
  }
  return 0;
}

int cmd_cfg_clear(int, char **) {
  cfg_erase("comp");
  cfg_erase("bind");
  printf("cleared (restart to boot with defaults)\n");
  return 0;
}

int cmd_restart(int, char **) {
  printf("restarting...\n");
  fflush(stdout);
  esp_restart();
  return 0;
}

void register_cmd(const char *cmd, const char *help, esp_console_cmd_func_t func) {
  esp_console_cmd_t c{};
  c.command = cmd;
  c.help = help;
  c.func = func;
  ESP_ERROR_CHECK(esp_console_cmd_register(&c));
}

} // namespace

size_t cfg_load(const char *key, uint8_t *buf, size_t cap) {
  nvs_handle_t h;
  if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK) {
    return 0;
  }
  size_t len = cap;
  const esp_err_t err = nvs_get_blob(h, key, buf, &len);
  nvs_close(h);
  if (err != ESP_OK) {
    return 0;
  }
  return len;
}

bool cfg_save(const char *key, const uint8_t *val, size_t len) {
  nvs_handle_t h;
  if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t err = nvs_set_blob(h, key, val, len);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return err == ESP_OK;
}

bool cfg_erase(const char *key) {
  nvs_handle_t h;
  if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK) {
    return false;
  }
  esp_err_t err = nvs_erase_key(h, key);
  if (err == ESP_OK) {
    err = nvs_commit(h);
  }
  nvs_close(h);
  return err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND;
}

void console_start() {
  esp_console_repl_t *repl = nullptr;
  esp_console_repl_config_t rc = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
  rc.prompt = "smgen>";
  rc.max_cmdline_length = 2048; // composition/binding hex は長い。
  rc.task_stack_size = 8192;

  esp_console_dev_usb_serial_jtag_config_t hw = ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
  esp_err_t err = esp_console_new_repl_usb_serial_jtag(&hw, &rc, &repl);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "console init failed: %s", esp_err_to_name(err));
    return;
  }
  register_cmd("cfg-comp", "Store composition TLV (hex) into NVS smgen/comp", cmd_cfg_comp);
  register_cmd("cfg-bind", "Store binding TLV (hex) into NVS smgen/bind", cmd_cfg_bind);
  register_cmd("cfg-show", "Show stored composition/binding blobs", cmd_cfg_show);
  register_cmd("cfg-clear", "Erase stored composition/binding blobs", cmd_cfg_clear);
  register_cmd("restart", "Reboot to apply the configuration", cmd_restart);
  ESP_ERROR_CHECK(esp_console_start_repl(repl));
  ESP_LOGI(TAG, "console ready (USB-Serial-JTAG): cfg-comp / cfg-bind / cfg-show / cfg-clear / restart");
}

} // namespace smgen
