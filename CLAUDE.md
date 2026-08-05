# FortiToolkit — 維護指引

FortiGate 設定檔離線稽核工具。單一 WinForms GUI（`FortiToolkit.ps1`），一次解析餵三條分析線：合規檢查、清理候選、重複值合併，外加一個網路檢視分頁。無 build step，純 PowerShell dot-source，不依賴任何外部模組。輸入是一份 config 匯出檔，輸出是勾選後生成的 CLI 與 CSV 報表。

## 檔案結構（完整可跑需這 5 檔，全在同一目錄）

| 檔 | 性質 | 對外提供 |
|----|------|---------|
| `FortiToolkit.ps1` | GUI 正本、事件接線、報表匯出，**手維護** | 進入點 |
| `FortiToolkit.Core.ps1` | 解析器、引用分析、重複偵測，**無任何 UI** | `Parse-FortiConfig` / `Invoke-Cleanup` / 共用 helper |
| `FortiToolkit.Rules.ps1` | 合規引擎 + 規則包 | `Invoke-Compliance` / `$script:Pack` |
| `FortiToolkit.Cli.ps1` | CLI 產生器、NCM 規則匯入與 lint | `Build-SafeCli` / `Build-DecideCli` / `Build-FixCli` |
| `FortiNetworkTab.ps1` | 網路檢視分頁（介面 / 路由 / VPN / 流量矩陣 / 服務） | 附加一個 TabPage |

**載入順序是硬需求**：主檔以 `foreach ($m in @('Core','Rules','Cli'))` 迴圈 dot-source 前三個模組，缺檔跳 MessageBox 後 return；`FortiNetworkTab.ps1` 在檔案最末、`$form.Add_Shown` 之前載入，因為它要用到已建好的 `$tabs` / `$tree` / `$fntMono` / `$form`。

**Core 的 helper 是全域共用的**：`Strip-Quotes` / `Split-Tokens` / `Join-Sorted` / `Get-MaskBits` / `New-Set` / `Test-Builtin` 被 Rules、Cli、NetworkTab 三邊直接呼叫。改 Core 的 helper 等於改三個檔的行為。

**本檔三層，分工不重複（同一件事只在所屬層講一次）**：**鐵則**（紅線，違反即產出錯誤 CLI 或誤判合規）→ **設計原則**（理念，改 code 自我檢查）→ **慣例**（PowerShell / WinForms 的具體 do / don't）。

---

## 鐵則

1. **CLI 註解永不接在指令後面** — FortiOS 把指令之後的一切當參數，`set status enable  # comment` 會被吃進去。`Build-*Cli` 產出的每個註解一律自成一行。這條在 `FortiToolkit.Cli.ps1` 檔頭也寫了一次，**不要「整理」成行尾註解**。

2. **引用分析不得引入欄位白名單** — `Invoke-Cleanup` 掃描每個物件的每個值，任何 token 命中已知物件名就算引用。誘惑是列一張「哪些欄位可能放引用」的表來加速，但那張表只要漏一個欄位就會**靜默地把在用的物件放進刪除清單**——失敗方向朝著刪除，這是最壞的方向。root 是推導出來的（不在 `WatchSet` 的物件即為 root），不是列舉的。

3. **合規規則跑物件樹，不跑文字** — 文字規則如 `config system admin(.|\n)*edit "x"(.|\n)*set trusthost1`，萬用字元會越過 `next` 走進下一個物件，**只要後面任一個帳號有該設定就報合規**。結構比對從根本上消掉這整類假通過：一條「每個 admin 都要有 trusthost」的規則一次只看得到一個物件。匯入的 NCM 規則因此只做 review 不執行（`Lint-TextRules`）。

4. **缺鍵 ≠ 未設定** — FortiOS 匯出時省略處於原廠預設的設定。每條斷言可宣告 `Default`，`Get-Val` 在鍵不存在時代入它，`Get-FailDetail` 會把這種值標成 `(default)`。**新增規則時先確認該設定的原廠預設值**，漏宣告 Default 會讓規則對著沒寫出來的設定誤報。

5. **內建物件永不進刪除清單** — `Test-Builtin`（名單 + 前綴）是硬停，獨立於引用分析之外。FortiOS 出廠物件在 config 檔裡合法地零引用，但刪不得。它們改列在 Overview 的 “BUILT-IN OBJECTS HELD BACK”。

6. **刪除前的 refcnt 驗證步驟不可從產出中拿掉** — config 檔看不到 FortiManager、SDN connector、裝置記憶體裡的引用。`Build-SafeCli` 產出的 Step 2 逐物件列出 `diagnose sys cmdb refcnt show`，Step 3 才是刪除區塊。**裝置才是權威，檔案不是。**

7. **重複值的刪除一律註解掉** — `Build-DecideCli` 產出的 `delete` 全部前綴 `#`。合併重複需要先把每一處引用改指到 keeper，不是批次操作。

8. **`Build-SafeCli` 的段落順序：群組先於成員** — 排序鍵把 `GroupSet` 內的 section 排到 0、其餘排 1。順序反了，刪成員時群組還指著它，FortiOS 回 `-23`。

9. **改完任一 `.ps1` 後，用絕對路徑確認產出目錄的成品**；純文件（本檔 / README）不需要。

---

## 設計原則（對照業界慣例）

改 code 前用這些自我檢查（「有沒有違反 X？」）：

- **SoC + 單向依賴** — 依賴方向 `GUI → Rules/Cli → Core → 資料`。Core 檔頭寫明 “No UI in this file”，**不得反向引用 `$form` / `$tabs` / 任何控制項**。NetworkTab 是唯一例外（它本來就是 UI 附加檔），但它只讀 `$script:Audit`，不寫。
- **Fail-safe direction（失敗要朝安全的方向倒）** — 引用分析寧可少刪（鐵則 2）、內建物件寧可留（鐵則 5）、文字規則寧可不執行（鐵則 3）。**判斷任何取捨時先問：這個失敗會朝哪個方向倒？** 「誤報一條要人工看」永遠優於「漏報一條讓人刪掉在用的物件」。
- **SSOT** — `$script:WatchSet` / `GroupSet` / `Builtin` / `SkipKeys` / `DupSec` / `CmdbPath` 都只在 Core 定義一次。嚴重度色票 `$script:SevColor`、排序 `$script:SevRank` 只在主檔定義一次。
- **No Magic Numbers** — 數字收進具名 hashtable。色票以 `@(r,g,b,r,g,b)` 六元組存放（前三 back、後三 fore）。
- **Determinism** — 同一份 config 兩次分析結果必須相同。排序一律用**預先算好的字串鍵**（`$g.SortKey`、`$r.SortKey`、`Get-RouteSortKey`），不靠 hashtable 列舉順序，因為 `.Keys` 的順序不保證。
- **Precomputed sort key** — 熱路徑的排序不要在 `Sort-Object` 運算式裡現算。既有三處都是建模時算一次、排序時只讀欄位。
- **Lazy evaluation** — 網路檢視只在使用者真的切到該分頁時才建模（`Fill-Network` + `ReferenceEquals` 快取），`Load-File` 不需要知道它存在。**新增分頁沿用這個模式**，別讓 `Load-File` 愈長愈肥。
- **Immutability** — 分析函式不 mutate 輸入的 `$Objects`。唯一例外是 `Load-File` 事後為 `$comp` 每筆補 `SortKey`，那是在同一個函式內、物件剛產生就補的。
- **Graceful degradation** — config 缺某個 section 時規則標 `Skip=$true` 而非 fail，Overview 分開統計為 “Not applicable”。**「沒有這個東西」不等於「這個東西不合規」。**
- **可追溯到原始碼行** — 每個物件帶 `L`（行號），`Show-Detail` 據此把 config 原文前後文印出來。**新增任何發現類型都要帶行號**，否則使用者無從查證。
- **Desktop WinForms，非響應式** — 版面靠 `Dock` + `SplitContainer` + 兩個手算座標的函式（`Update-TopLayout` / `Update-CliBar`，都由 `Add_SizeChanged` 驅動）。**不要引入自動佈局容器改寫既有版面**，混用會讓手算座標失準。

---

## PowerShell 慣例

- **`$null` 放比較式左邊** — `if ($null -eq $x)`。右邊放 `$null` 時若左邊是陣列，`-eq` 變成**過濾運算**而非布林判斷，回傳的是符合的元素集合。純量變數不受影響，但養成習慣比逐一判斷便宜。
- **`[void]` 的使用時機** — `ArrayList.Add()` / `StringBuilder.Append*()` / `DataTable.Rows.Add()` / `TabPages.Add()` 會吐回傳值污染 pipeline，要 `[void]`。**泛型 `List[object]` 的 `Add()` 本身回 void，不要加**（Core 檔頭有記這件事）。
- **集合一律用 `[System.Collections.Generic.List[object]]::new()`** — 不用 `@()` 累加（每次 `+=` 都重建整個陣列，在數萬筆的熱路徑上是災難）。
- **hashtable 查找取代巢狀迴圈** — 建索引時用巢狀 hashtable（`vdom → name → objects`）而非字串內插鍵（`"$v|$n"`），熱路徑上每次查找都少配置一個字串物件。非熱路徑用內插鍵可讀性較好，兩種寫法在 codebase 內並存是刻意的。
- **函式動詞** — 目前有 `Fill-` / `Strip-` / `Lint-` / `Fit-` / `Apply-` / `Sync-` / `Parse-` / `Load-` / `Refresh-` 等非核准動詞。**現況接受**（腳本不是模組，不會觸發 `Import-Module` 警告）；但**新增函式請用核准動詞**（`Get-` / `Set-` / `New-` / `Test-` / `Update-` / `Remove-` / `Invoke-` / `Build-`），別擴大既有例外。
- **`$script:` 前綴表示跨函式共享狀態** — GUI 狀態（`$script:Audit` / `$Lines` / `$Path` / `$CurZone` / `$Suspend` / `$ShowPass`）與各種 per-tab 註冊表（`$Grids` / `$Tables` / `$Recs` …）一律 `$script:`。控制項變數則不加（`$form` / `$tabs` / `$txtCli`），因為它們在 script scope 建立後只讀不換。
- **路徑一律 `$here`，不用 `$PSScriptRoot`** — 主檔開頭已建好 `$here = $PSScriptRoot`，並在 dot-source / ISE 情境下 fallback 到 `$MyInvocation`。**任何載入其他檔案的地方都用 `$here`。**
- **`-LiteralPath`** — 檔案操作一律用它，config 檔名可能含 `[` `]`。
- **編碼** — 讀檔 `[System.IO.File]::ReadAllLines()`；寫檔 `WriteAllText` 搭 `New-Object System.Text.UTF8Encoding $true`（帶 BOM，Excel 開 CSV 才不會亂碼）。

## WinForms 慣例

- **勾選狀態的批次變更一律包 `$script:Suspend`** — `Set-TypeTicks` / `Set-AllTicks` 在迴圈前後設定此旗標，`Add_CellValueChanged` 開頭檢查它直接 return。否則勾 500 列會觸發 500 次 `Refresh-Cli`，每次重建整段 CLI 字串。
- **DataGridView 的 checkbox 需要 `CurrentCellDirtyStateChanged` + `CommitEdit`** — 否則勾選要等焦點離開該格才會寫進 DataTable。三個 grid 都掛了，新增 grid 別漏。
- **欄位以名稱存取，不以索引** — `$row.Cells['Fix']` / `$row.Cells['Ref']`。目前 `Add_CellValueChanged` 還留著 `$e.ColumnIndex -ne 0` 的硬編（Fix 恆為第 0 欄），**這是既有技術債，別擴散**。
- **篩選用 `DataView.RowFilter`，不重建 DataTable** — `Apply-View` 切 zone 時只換 view。字串值要 `.Replace("'", "''")` 逃逸。
- **`ShowDialog()` 是 STA 依賴** — 剪貼簿 `Clipboard::SetText` 在 MTA 執行緒會拋例外，PowerShell 7 預設 MTA。檔頭已註明需 `-STA`，程式碼另有 try/catch 降級到狀態列訊息。
- **控制項加入順序決定 Dock 疊放** — WinForms 中後加入的 `Dock='Top'` 會被排在先加入者之上。`New-GridTab` 的 `Add` 順序（`el` → `g` → `sp` → `fp` → `lb`）是刻意的，別重排。
- **文字輸出到 TextBox 前要 `-replace "\`n", "\`r\`n"`** — 多行 TextBox 只認 CRLF，LF 會擠成一行。`Build-Overview` / `Build-RulePack` / `Show-Detail` 都做了。

---

## 規則包慣例（改 `$script:Pack` 前必讀）

- 目前 **33 條規則、8 個分類**（Administrative access / Exposed services / SNMP / Logging / Firewall policy / VPN / Password policy / System hygiene）。
- 引擎支援四種 `Mode`：`each` / `section` / `exists` / `absent`。**目前只用到 `each`（15）與 `section`（18）**，另兩種是引擎能力但無現行規則使用。
- `Op` 共 14 種（見 Rules 檔頭）。新增規則優先用既有 Op，需要新 Op 時同步改 `Test-Cond` 與 `Get-FailDetail` **兩處**——漏改後者會讓失敗訊息退化成沒有上下文的 `key = value`。
- **每條規則必須有 `Why`**，而且要寫「不做會怎樣」而非重述規則本身。`Show-Detail` 會原樣顯示給使用者看。
- `Zone` 三值：`global`（僅全域，VDOM 關閉時忽略）/ `vdom`（除 global 外每個 VDOM）/ `any`（每個 zone）。
- `Fix` 裡需要站點特定值的行以 `#` 開頭。`Build-FixCli` 原樣輸出，使用者會直接貼進裝置。

## 命名原則

- **大小寫傳達可變性** — 真正不可變的設定用 ALL_CAPS 或 `$script:PascalSet` 形式的註冊表；運行期狀態用 camelCase。
- **短名限縮在單一函式內** — Core 的物件欄位刻意用單字母（`V` vdom / `S` section / `N` name / `T` settings table / `L` line），因為它們在數十萬次迭代的熱路徑上反覆出現、且集中在一個檔案內。**跨檔案的公開結構請用完整名稱**（`Ifaces` / `Routes` / `Pairs` / `VdomPol`）。
- **名稱說明意圖，不說明型別** — `$sawVdom` 比 `$vdomBool` 好。
- **函式名以動詞開頭**，說明它做什麼而非回傳什麼。

## 文件慣例

- **不寫死可變數字** — 規則數、分類數以外，別在文件裡寫死某份 config 的 router 數 / policy 數，用結構或量級表述。
- 效能說明要標明**量級與前提**（例：8 萬行 config 上的可達性走訪約數十萬次迭代），別寫成絕對秒數。

---

## 已知技術債（動到相關區域時一併處理）

- **分頁索引硬編碼** — `Load-File` 用 `$tabs.TabPages[1..3]` 更新標題、`$btnRules` 用 `TabPages[5]` 切頁。目前順序剛好對得上，且 `FortiNetworkTab.ps1` 靠「附加在最後」的約定維持有效，但這個約束只寫在註解裡。**正解是改用 `$tp.Tag` 查找**（`New-TextTab` 需補 Tag 參數）。
- **`$tabs.Add_SelectedIndexChanged` 註冊了兩次** — 主檔一次（`Refresh-Cli`）、NetworkTab 一次（`Fill-Network`）。行為正確但切到 Network 分頁時 `Get-TabKey` 回 `$null`，會先清空一次 `$txtCli` 再於切回時重建，視覺上會閃。
- **`Add_CellValueChanged` 的 `$e.ColumnIndex -ne 0`** — 假設 Fix 欄恆在索引 0。改 `New-GridTab` 的欄位順序會靜默失效。
