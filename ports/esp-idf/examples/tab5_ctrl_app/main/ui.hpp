// LVGL の画面(Tab5 = 1280x720 横向き)。docs/design/p4-thread-controller.md §9.1「画面(v1)」。
//
// 契約: このファイルの中で sm_ctrl_* / ot_* を呼ばない。pump への依頼は
// sm_app_post_op()、pump からの状態は sm_app_snapshot_get() だけを使う。

#pragma once

// 画面を組む(LVGL ロックを取った状態で app_main から呼ぶ)。
// 500ms のタイマを仕掛けてスナップショットを反映し続ける。
void sm_ui_create();
