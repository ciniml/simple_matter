// 全テストの束ね。
//
// Node 22 未満の `node --test` は **ディレクトリ引数を解釈しない**(パスを
// モジュールとして解決しようとして `Cannot find module .../test` で落ちる)。
// このファイルがあることで `node --test web/configurator/test/` がディレクトリ →
// `index.js` として解決され、下の import 群で全テストが登録される。
//
// Node 22 以降ではディレクトリ探索が効くため、各 `*.test.js` と本ファイルの
// 両方が実行される(= 同じテストが 2 回走るだけで、失敗にはならない)。
// 個別に走らせたいときは `node --test web/configurator/test/*.test.js`。

import "./tlv.test.js";
import "./spake2p.test.js";
import "./onboarding.test.js";
import "./nvs.test.js";
import "./smscript.test.js";
import "./flash.test.js";
