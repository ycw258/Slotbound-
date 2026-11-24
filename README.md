# Slotbound-
# 《SlotBound》Lua 运行时注入分析

> 研究笔记 · 目标版本 1.0.0（LÖVE 11.5 / LuaJIT）· Windows x64
>
> 本文只讨论**分析与实现原理**，不提供游戏本体、破解补丁或游戏资源。请使用你合法拥有的游戏，
> 所有实验均在离线单机环境下完成。

---

## 0. 摘要

《SlotBound》是一款基于 LÖVE 11.5 的「老虎机 + 自走棋」单机游戏。它的全部游戏逻辑都是 Lua，
但被打包进一个加密且带签名的自定义资源包。本文记录了从静态侦察、包格式判断、存档执行环境验证，
到在运行时把 Lua 脚本注入游戏状态机、定位关键全局变量、还原转盘结算逻辑的完整过程。

核心结论有三点：

1. `Slotbound.dat` 采用 AES 加密 + 签名校验，**改包这条路不可行**；
2. 存档虽然是明文 Lua，但加载时被 `setfenv` 沙箱隔离，**无法作为代码注入点**；
3. 通过 **IAT Hook + 手写 x64 shellcode** 可以拿到 `lua_State*`，进而执行任意 Lua，
   之后的一切（数值、盘面）都只是对游戏自身全局表的读写。

---

## 1. 研究对象与边界

| 项 | 内容 |
|---|---|
| 目标 | SlotBound 1.0.0（Steam AppId 2226700） |
| 引擎 | LÖVE 11.5.0 "Mysterious Mysteries" + LuaJIT |
| 平台 | Windows 10/11 x64 |
| 分析方式 | 静态侦察 + 运行时动态验证 |
| 不做的事 | 不修改、不重打包游戏文件；不提供任何游戏资源 |

工程环境：Python 3.12（`ctypes` 调 Win32 API），无编译器、无第三方注入库。

---

## 2. 静态侦察

### 2.1 文件布局

游戏目录的构成已经能说明很多问题：

```
Slotbound.exe            624 KB   自研 C++ 加载器
love.dll                 4.7 MB   LÖVE 运行时
lua51.dll                567 KB   Lua 5.1 兼容层（实为 LuaJIT）
SDL2.dll / OpenAL32.dll          平台与音频
Slotbound.dat            134 MB  加密资源包
errorlog.txt                     运行时诊断日志
```

几个关键判断：

- **`Slotbound.exe` 只有 624 KB**，且用 ASCII 搜索不到 `LOVE` 融合标记、`zip` 的 `PK` 头，
  说明游戏代码不在 exe 里，走的是「外部资源包 + 自研加载器」路线。
- `love.dll` + `lua51.dll` 的组合，加上 `errorlog.txt` 里的 `love=11.5.0`，可以直接确定引擎版本。
- `lua51.dll` 只有 567 KB，而官方 LÖVE 11.5 默认用 LuaJIT（该 DLL 名为了 API 兼容仍叫 `lua51.dll`），
  后续实验也印证了这一点：所有数字都是裸 double，没有 16 字节的 `TValue` 类型标签。

### 2.2 资源包格式：SBDAT008

`Slotbound.dat` 的首部是：

```
53 42 44 41 54 30 30 38 | 00 | 88 09 00 00 | 00 00 00 00 | 82 75 06 08 | 00 00 00 00 | ...
" S B D A T 0 0 8 "      版本位   0x0988        0          0x08067582      0
                                (2440)                  (134,641,026)
```

可以读出：8 字节魔数 `SBDAT008`、1 字节版本位、4 字节索引长度（2440）、4 字节保留、4 字节数据长度
（≈134.6 MB）、4 字节保留。文件**尾部还有一份相同的 `SBDAT008`**，其后跟 48 字节——典型的「尾部签名块」布局。

包体从第 25 字节开始就是高熵数据（4 MB 采样内 256 种字节值均匀分布、找不到任何明文路径或 Lua 关键字），
配合 exe 导入表里的 `BCryptDecrypt`、`BCryptCreateHash`、`BCryptVerifySignature`、`BCryptImportKeyPair`，
以及字符串 `slotbound:file:v6`、`slotbound:index:v6`、`SBIDX006`，可以确定：

- 每个文件用**派生密钥 + AES 对称加密**；
- 整包用**非对称签名**做完整性保护（公钥内嵌在 exe）。

**结论**：即便破解了密钥，重新打包后签名也无法通过。改包路线放弃。

### 2.3 存档是可读的

```
%APPDATA%\slotbound_full\save_fallback.dat
```

内容是一段明文 Lua：

```lua
return {["upgrades"]={["unlock_faction_arcane"]=true,...},
        ["originite"]=23, ["achievements"]={...}, ["settings"]={...}, ...}
```

`.bak` 是上一份存档，命名里的 `fallback` 说明它可能是主存档缺失时的兜底。

### 2.4 存档执行环境验证（重要）

存档是 Lua 源码，最常见的加载方式是 `loadstring` + 直接执行。若如此，只要在 `return {...}` 之前插入代码，
就能拿到游戏全局环境——这是最省事的注入点，所以值得先验证。

**实验设计**：在存档最前面插入一段 pcall 包裹的探针，尝试用三种方式留痕：

```lua
pcall(function()
  local f = io.open([[C:\...\_probe.txt]], "w")
  if f then f:write("io_ok " .. tostring(_VERSION)) f:close() end
end)
pcall(function() love.filesystem.write("_probe2.txt", "lf_ok") end)
```

同时把存档里的 `originite` 改成 `999999`，作为「存档确实被读取」的对照。

**结果**：

- 两个探针文件都**没有生成**；
- 但内存扫描能在进程里找到 `999999` 的 double（说明存档确实被解析、值确实生效）；
- 游戏运行正常，没有报错弹出。

**结论**：存档是通过 `loadstring` 加载、并在**受限环境**（`setfenv` 到一个没有 `io`/`love` 的沙箱表）里执行的。
数据可改，代码执行不了。存档注入路线放弃。

---

## 3. 运行时注入方案

### 3.1 方案对比

| 方案 | 可行性 | 原因 |
|---|---|---|
| 改资源包 | ✗ | AES + 签名，重打包必然验签失败 |
| 改存档注入代码 | ✗ | `setfenv` 沙箱，无 `io`/`love` |
| 替换 `love.dll` / `lua51.dll` | △ | 需编译环境与完整导出转发，代价高 |
| **IAT Hook + shellcode** | ✓ | 纯脚本可完成，不落盘、不改文件、不需要编译器 |

### 3.2 hook 点的选择

`love.dll` 的导入表里有一批来自 `lua51.dll` 的函数。手工解析 PE 得到它们的 IAT RVA，例如：

| 导入函数 | IAT RVA |
|---|---|
| `lua_pcall` | `0x2db0b8` |
| `luaL_checknumber` | `0x2db130` |
| `luaL_loadbuffer` | `0x2db2e8` |

选择 `luaL_checknumber` 的理由：

1. 它是一个「取第 N 个数值参数」的校验函数，**几乎每帧都会被调用若干次**；
2. 它的第一个参数永远是 `lua_State*`，也就是我们最想要的东西；
3. 它不参与渲染状态，替换成一次额外的 Lua 调用不会影响绘制。

### 3.3 地址计算与 ASLR

被 hook 的函数地址每次都不同，因此不能写死。做法是：

```
目标地址 = 目标进程内 lua51.dll 的模块基址 + 该导出函数在 PE 导出表里的 RVA
```

模块基址用 `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` 枚举得到；
导出 RVA 直接在磁盘上的 `lua51.dll` 里解析导出目录（名字表 → 序号表 → 地址表）。
这样无论 ASLR 如何随机化都能算对。

### 3.4 shellcode 设计

Win64 调用约定下，函数入口处 `rcx = lua_State*`，`rsp % 16 == 8`。stub 必须做到：
保存易失参数、保证调用前 16 字节对齐、留出 32 字节 shadow space、只执行一次、最后**尾调用**回原函数。

```asm
sub rsp, 0x68              ; shadow(32) + 保存区(32) + 对齐(8)
mov [rsp+0x20], rcx        ; L
mov [rsp+0x28], rdx
mov [rsp+0x30], r8
mov [rsp+0x38], r9
mov rax, FLAG
cmp dword [rax], 0         ; 已经执行过就直接放行，防止 pcall 递归
jne skip
mov dword [rax], 1
mov rcx, [rsp+0x20]        ; L
mov rdx, SCRIPT            ; Lua 源码地址
mov rax, luaL_loadstring
call rax                   ; 编译脚本 → 函数入栈
mov rcx, [rsp+0x20]
xor edx, edx               ; nargs = 0
xor r8d, r8d               ; nresults = 0
xor r9d, r9d               ; errfunc = 0
mov rax, lua_pcall
call rax                   ; 执行脚本
skip:
mov rcx, [rsp+0x20]        ; 还原原始参数
mov rdx, [rsp+0x28]
mov r8,  [rsp+0x30]
mov r9,  [rsp+0x38]
add rsp, 0x68
mov rax, ORIGINAL
jmp rax                    ; 尾调用，游戏侧完全无感
```

这段机器码由 Python 逐字节拼出（`48 83 EC 68` / `48 89 4C 24 20` …），没有引入汇编器。

### 3.5 内存布局与触发

```
[+0x000] shellcode
[+0x200] flag（4 字节）
[+0x240] Lua 源码（NUL 结尾）
```

流程：

1. `VirtualAllocEx(PAGE_EXECUTE_READWRITE)` 申请内存并写入上述内容；
2. `VirtualProtectEx` 把 IAT 所在页改为可写；
3. 把 IAT 槽写成 stub 地址，恢复页保护；
4. 游戏下一次调用 `luaL_checknumber`，flag 翻转、脚本执行；
5. 之后每次调用都因 flag 已置位而直接尾跳，开销可忽略。

重复注入时，先从旧 stub 尾部解出「原始函数地址」再重新挂钩，避免链条越套越长。

---

## 4. 注入之后：信息收集

脚本一旦跑起来，就可以 `pairs(_G)`。这个游戏的全局命名相当扁平，能直接看到：

| 类别 | 观察到的全局 |
|---|---|
| 货币 | `coins`、`displayCoins`、`jungsu`、`displayJungsu` |
| 转盘 | `spinCost`、`spinCostStep`、`spinsLeft`、`spinsInWave`、`freeSpinCredits` |
| 战斗 | `battlefield.baseHP`、`battlefield._prevBaseHP`、`battlefield.originitePending` |
| 盘面 | `slot.grid`、`slot.spin`、`slot.result`、`slot.forceWinOnce` |
| 菜单 | `phase`、`ui.*` |

另外还有一个很有用的聚合函数 `collectRunState()`，它返回当前 run 的完整快照：

```lua
{ economy = { coins = 999999, spinCost = 0, jungsu = 2, spinsLeft = 6, ... },
  battlefield = { baseHP = 999, originitePending = 9999, ... },
  slot = { grid = {...} }, machine = "nudge", ... }
```

用它可以快速确认「我们改的值是不是游戏自己认的值」——如果 `collectRunState()` 里也变了，
说明改的是真状态，而不是某个缓存副本。

---

## 5. 转盘（slot）机制分析

### 5.1 模块结构

`slot` 是一个模块表，关键成员：

| 成员 | 类型 | 说明 |
|---|---|---|
| `grid` | table | 当前盘面，`grid[列][行]`，3×3 |
| `spin` | table | 旋转动画状态：`active` / `started` / `t` |
| `result` | table | 结算状态：`won` / `checked` / `awarded` / `highlightActive` |
| `forceWinOnce` | boolean | 内置的「下一转必中」开关 |
| `startSpin` | function | 旋转入口（**方法调用**） |
| `buildResultGrid` | function | 生成结果盘面 |
| `evaluateGrid` | function | 按盘面结算 |
| `evaluateWin` | function | 中奖判定 |
| `getWinningLinesDefinition` | function | 中奖线定义 |
| `nudgeColumn` / `annotateNudgePlan` | function | 微调（nudge）相关 |

### 5.2 盘面与中奖线

`getWinningLinesDefinition()` 返回 8 条线，坐标是 `{列, 行}`：

```
1~3: 三条竖线    4: 主对角线    5: 副对角线    6~8: 三条横线
```

盘面符号是单字母：`W`、`M`、`A`、`H`、`S`、`D`（`J` 属于特殊符号，由特定核心触发）。
单位对象里也带同一个字段：`unit.sym = "W"`，说明盘面符号直接决定生成哪一类单位。

### 5.3 符号权重与中奖档位

游戏自己的常量模块 `src.data.constants.slot` 里写得非常清楚：

```lua
symbolWeights = { A = 0.20, D = 0.10, H = 0.15, M = 0.15, S = 0.20, W = 0.20 }
winTiers = {
  { key = "jackpot",   lines = 5 },
  { key = "overdrive", lines = 4 },
  { key = "burst",     lines = 3 },
}
forceWinProb = 0
winSuppressProb = 0
```

也就是说：**连线数 ≥5 就是最高档 jackpot**。9 格同符号会产生 8 条线，必然落在最高档。

### 5.4 旋转流程（推断 → 验证）

从调用链和状态字段可以还原出：

```
startSpin → buildResultGrid → 播放滚动动画 → evaluateGrid → evaluateWin → 发放奖励
```

验证方式与两个「小坑」：

- 直接 `slot.startSpin()` 会报 `src/game/slot.lua:0: attempt to index a nil value`。
  原因是它是**冒号方法**，需要把 `slot` 自己作为 `self` 传入；`slot:startSpin()` 立刻成功。
- 用鼠标点拉杆触发一次真实旋转并用包装函数打日志，可以确认调用序列：
  `startSpin(self)` → `buildResultGrid(self)` 返回 3×3 表 → `evaluateGrid(self, grid)` → `evaluateWin(self)`。

### 5.5 两个可控点

**（a）`forceWinOnce`**：游戏内置的「下一转必中」。置 `true` 后执行一次旋转，
结果盘面会出现成线的组合，`slot.result.won == true`，随后该标志自动复位。

**（b）`buildResultGrid` 的返回值**：它是唯一产出生盘面的函数，返回 `{列}{行}` 的 3×3 表。
只要在返回前替换掉，就能让每一转都出指定盘面：

```lua
local orig = slot.buildResultGrid
slot.buildResultGrid = function(self, ...)
  local g = orig(self, ...)
  if FORCE_GRID then
    local out = {}
    for c = 1, 3 do out[c] = { FORCE_GRID[c][1], FORCE_GRID[c][2], FORCE_GRID[c][3] } end
    return out
  end
  return g
end
```

实测：把盘面设成 9 格全 `W` 后旋转，`slot.grid` 变为全 `W`，`slot.result.won == true`；
再设成全 `M`，结果同步变成全 `M`，证明覆盖点确实在「生成」这一步，而不是渲染层。
把钩子还原后，盘面恢复自然随机。

### 5.6 逆向技巧：字节码常量提取

LuaJIT 会把函数名、全局名、字符串字面量都放进函数的常量段。于是有一个很好用的静态手段：

```lua
local dump = string.dump(slot.buildResultGrid)          -- 导出字节码
local text = dump:gsub("[%z\1-\31\127-\255]", "\n")     -- 过滤不可打印字节
-- 剩下的可读单词里，就能看到 forceWinOnce、sandboxNextWinLines、stoneUnitsByLine 等线索
```

`buildResultGrid` 的常量里直接出现了 `forceWinOnce`、`sandboxNextWinLines`、`sandboxNextWinSymbol`，
这就解释了为什么「必中」和「指定盘面」都成立——游戏本来就为沙盒测试留了这两个入口。

---

## 6. 表现层：叠加菜单

注入只解决「能执行」，用户界面仍然要自己画。做法是包装 LÖVE 的回调（这些回调在 `love` 表里是
**动态查找**的，替换即生效）：

| 回调 | 用途 |
|---|---|
| `love.update` | 每帧刷新状态、应用锁定值；开启「暂停」时跳过原函数 |
| `love.draw` | 在原绘制之后叠加面板（`push("all") / origin() / pop()` 重置变换） |
| `love.mousepressed` / `mousemoved` / `mousereleased` | 命中检测、拖动面板；未命中则转发给游戏 |
| `love.keypressed` | F1 开关、Esc 关闭、输入框回删/确认 |
| `love.textinput` | 数字输入（只接受 `0-9 . -`） |

两个工程细节：

- **字体复用**：直接读游戏自己的中文像素字体 `src/data/font/Chinese/arkpixel10.ttf` 新建
  `Font` 对象，中文不会出现豆腐块；但该字体的拉丁字母字形很怪（`W` 看起来像 `H`），
  所以符号标签单独用默认字体或直接换成一个汉字。
- **命中框每帧重建**：按钮矩形在 `draw` 里生成并登记，点击时倒序查表；
  这样面板拖动、数值变化都不需要额外同步坐标。

面板与外部（命令行）通过两个文本文件解耦：指令文件 + 状态文件，双方各自读写，避免跨进程通信的复杂度。

---

## 7. 工程细节与可靠性

| 问题 | 处理 |
|---|---|
| 递归调用 | stub 内置 flag，确保脚本只执行一次 |
| 多次注入 | 先从旧 stub 尾部解出真正目标地址，再重新挂钩 |
| 异常影响游戏 | 所有 Lua 补丁放在 `pcall` 里，失败静默降级 |
| 恢复原状 | 保存原始 `love.*` 回调与 `buildResultGrid`，一键还原 |
| 中文字体缺失 | 字体加载失败时回退到默认字体 |

---

## 8. 局限

- 纯内存态方案，**游戏重启后注入即失效**，需要重新执行。
- 依赖 `love.dll` 中 `luaL_checknumber` 的 IAT 位置（当前 `0x2db130`）；游戏更新后需要重新定位。
- 只在单机/离线环境有意义；联机场景中使用属于作弊。

---

## 9. 方法论总结

这次分析里真正可复用的东西：

1. **先判断边界**：改包 > 存档 > 注入 > 替换 DLL，按成本从低到高试，每一步都用实验证伪
   （存档探针那个实验十分钟就省掉了后面所有弯路）。
2. **找高频、参数干净的函数做 hook 点**：`luaL_checknumber` 的 `rcx` 永远是 `lua_State*`。
3. **地址全部运行时算**：模块基址 + 导出 RVA，天然免疫 ASLR。
4. **尾调用式 hook**：保存/恢复易失寄存器、对齐栈、最后 `jmp` 回原函数，调用方完全无感。
5. **善用字节码常量**：`string.dump` + 过滤不可打印字符，是拿不到源码时最快的语义线索来源。
6. **用游戏自己的状态函数验证**（`collectRunState`），比看界面靠谱。

这些技能同样适用于 Windows 用户态的二进制分析、游戏安全研究与 CTF 逆向题目。

---

## 10. 声明

- 本文为个人学习与研究记录，**不包含**游戏本体、破解补丁或任何游戏资源文件。
- 请仅在你自己合法拥有的游戏副本、离线单机环境下复现本文实验。
- 请勿将相关技术用于联机游戏、商业用途或任何侵犯他人权益的场景。
- 使用相关技术可能违反游戏用户协议，风险自负。

