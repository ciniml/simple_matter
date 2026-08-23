// OpenThread のコンパイル時設定の上書き(CONFIG_OPENTHREAD_HEADER_CUSTOM)。
// このファイルは openthread-core-esp32x-ftd-config.h の**先頭**で include される
// ため、ここでの #define が IDF 既定より優先される。
//
// なぜ必要か(F8 の罠): IDF v5.4 では OPENTHREAD_CONFIG_SRP_SERVER_ENABLE が
// `#if CONFIG_OPENTHREAD_BORDER_ROUTER` の中でしか 1 にならない。しかし
// CONFIG_OPENTHREAD_BORDER_ROUTER=y にすると border agent の meshcop mDNS 配線
// (espressif/mdns managed component + otBorderAgent*)まで引き込まれ、backbone を
// 張らない自己完結ハブには過剰(リンクエラーにもなる)。SRP サーバだけをここで
// 有効化する。docs/design/p4-thread-controller.md §3 F8c。

#pragma once

// SRP サーバ(Thread デバイスの _matter._tcp 登録を受ける = このハブが DNS-SD の出所)。
#define OPENTHREAD_CONFIG_SRP_SERVER_ENABLE 1

// SRP サーバは署名検証に ECDSA を使う。IDF の ftd config は ECDSA を
// BORDER_ROUTER / SRP_CLIENT のときしか 1 にしないため、ここで明示する
// (srp_server.hpp が #error "OPENTHREAD_CONFIG_ECDSA_ENABLE is required" を出す)。
#define OPENTHREAD_CONFIG_ECDSA_ENABLE 1
