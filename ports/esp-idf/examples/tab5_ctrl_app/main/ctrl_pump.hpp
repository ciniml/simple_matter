// コントローラ pump タスク(sm_ctrl_* を専有する唯一のタスク)。
// docs/design/p4-thread-controller.md §9.1。

#pragma once

// pump タスクを起動する(静的スタック 128KB)。app_main から 1 回だけ呼ぶ。
// 呼び出し前に nvs_flash_init / esp_netif_init / esp_event_loop_create_default と
// sm_app_state_init() を済ませておくこと。
void sm_ctrl_pump_start();
