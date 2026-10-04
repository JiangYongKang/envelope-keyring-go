# envelope-keyring-go

基于**本地多版本密钥环**的信封加密（Envelope Encryption）与**密钥轮换**模拟库。
密钥材料仅存在于内存，重点演示：

- 新数据始终由**当前激活密钥**封装；解密严格按**密文自携带的密钥标识**选密钥；
- 轮换时**保留历史密钥**用于解密，轮换与并发加解密安全共存；
- 支持**加密上下文绑定**（如租户标识/用途）：解密必须提供同一段上下文，
  上下文不匹配返回可区分的 `ErrContextMismatch`；
- 密文格式支持**版本演进**（v1/v2/v3 可在同一密钥环下混用），当前写出版本 v3
  对**头部每一个字节**做完整性保护；跨版本重排、未知版本均被明确拒绝；
- 所有失败均归类为**可区分的哨兵错误**，绝不回退到错误密钥、绝不静默返回明文。

## 快速开始

```go
ring := envelope.NewKeyRing()
_ = ring.AddKey("k1", keyBytes32, true)          // true = 立即激活
svc := envelope.NewEnvelopeService(ring)

ct, err := svc.Seal([]byte("敏感数据"))           // 当前激活密钥 + 当前格式(v3)
pt, err := svc.Open(ct)                          // 按密文内 keyID 选密钥

// 绑定加密上下文（多租户场景）：解密必须提供同一段上下文
ctx := []byte("tenant=acme|purpose=billing")
ct2, _ := svc.SealWithContext([]byte("租户数据"), ctx)
pt2, _ := svc.OpenWithContext(ct2, ctx)          // 上下文不一致 => ErrContextMismatch

_ = ring.Rotate("k2", newKeyBytes32)             // 轮换：k2 激活，k1 转 retired
pt3, _ := svc.Open(ct)                           // 旧密文仍可由 k1(retired) 解密
```

## 密钥生命周期与轮换语义

| 状态 | 能否 Seal 新数据 | 能否 Open 历史密文 | 说明 |
|---|---|---|---|
| `active` | 是（唯一） | 是 | 同一时刻至多一个 |
| `retired` | 否 | 是 | 轮换后旧密钥的状态，专用于解历史密文 |
| `revoked` | 否 | 否，返回 `ErrKeyRevoked` | 怀疑泄漏时使用，命中即拒绝 |

- `Rotate(id, key)` = 追加新密钥并激活，旧激活密钥转为 `retired`（**不删除材料**）。
- 并发模型：`KeyRing` 内部使用 `sync.RWMutex`。Seal/Open 只持读锁获取密钥条目
  （拿到条目后加密在锁外进行），轮换/撤销持写锁。读操作只会观察到轮换前或轮换后的
  **完整一致状态**；轮换只改旧密钥状态、不清除其材料，因此进行中的 Seal/Open 不会失效。
- 密钥材料永不通过 `Keys()` 等接口对外暴露；入环时做一次防御性拷贝；DEK 用完清零。

## 密文格式

所有密文以 4 字节魔数 `E K R 1` 开头，随后是 1 字节版本号。解析顺序固定为：
**先校验魔数 → 再分派版本 → 严格按长度字段边界解析**。

### v1（`0x01`，历史格式，只读）

```
MAGIC(4)="EKR1" | VER(1)=0x01 | KEYIDLEN(1) | KEYID(…)
| DEKLEN(2,BE) | ENC_DEK(…)                     # 内含 12 字节 wrapNonce 前缀
| NONCE(12, 定长) | CIPHERTEXT+TAG(…)           # AES-256-GCM
```

### v2（`0x02`，历史格式，只读）

```
MAGIC(4)="EKR1" | VER(1)=0x02 | FLAGS(1)
| KEYIDLEN(2,BE) | KEYID(…)                     # 密钥标识长度扩展到 64KiB
| DEKLEN(2,BE) | ENC_DEK(…)                     # wrapNonce(12) || GCM(KEK, DEK)
| NONCELEN(1) | NONCE(…)                        # nonce 长度自描述
| TIMESTAMP(8,BE, Unix 秒)                      # 新增封装时间戳
| CIPHERTEXT+TAG(…)                             # AES-256-GCM
```

### v3（`0x03`，当前写出版本：严格头部完整性 + 上下文绑定）

```
MAGIC(4)="EKR1" | VER(1)=0x03 | FLAGS(1)
| KEYIDLEN(2,BE) | KEYID(…)
| NONCELEN(1) | NONCE(…)
| TIMESTAMP(8,BE, Unix 秒)
| CTXCHECK(32)                                  # HMAC-SHA256(DEK, 域常量‖上下文)
| DEKLEN(2,BE) | ENC_DEK(…)                     # wrapNonce(12) || GCM(KEK, DEK)
| CIPHERTEXT+TAG(…)                             # AES-256-GCM
```

v3 的两层 GCM AAD 直接覆盖头部字节（ENC_DEK 前移到头部末尾，使前缀切片可用）：

- 封装 AAD = `域常量 ‖ 头部前缀(MAGIC…DEKLEN)`；
- 正文 AAD = `域常量 ‖ 完整头部(MAGIC…ENC_DEK)`。

两层合并后，**头部每一个字节都至少被一层 GCM 认证标签覆盖**：
改动 FLAGS/KEYIDLEN/KEYID/NONCE/TIMESTAMP/CTXCHECK/DEKLEN 中任意一字节，
都会在解封装或正文验签阶段被拒绝（长度类字段还同时受解析边界检查约束）。

### 信封结构（各版本相同的密码学骨架）

1. 每次 Seal 生成随机 32 字节数据密钥 `DEK`；
2. `ENC_DEK = wrapNonce(12) || AES-GCM-Seal(KEK=激活密钥, DEK, AAD)`；
3. `CIPHERTEXT = AES-GCM-Seal(DEK, plaintext, AAD)`。

AAD 的构造随版本演进（解密严格按密文声明的版本选择对应构造）：

| 版本 | AAD 内容 |
|---|---|
| v1 | `用途常量 ‖ keyID`（最初的字节布局，保持不变以兼容历史密文） |
| v2 | `用途常量 ‖ 0x02 ‖ keyID`（版本字节纳入绑定） |
| v3 | `用途常量(v3 域) ‖ 头部字节`（全头部完整性保护） |

因此：
- 把密文的 keyID 改成**另一个环内密钥** → 用该密钥解封装时标签校验失败；
- 把密文搬到别的上下文 / 用错密钥 → 同样验签失败；
- 任何明文字节、nonce、封装块被翻转 → `ErrCiphertextModified`；
- 把一个版本的密文字段**按另一版本的布局重排** → 两版本 AAD 不同，验签必失败。

## 加密上下文绑定（多租户语义）

`SealWithContext(plaintext, context)` 把一段调用方提供的上下文（如
`tenant=acme|purpose=billing`）绑定到密文上：

- 上下文**本身不写入密文**（密文中不会出现上下文原文），而是以
  `CTXCHECK = HMAC-SHA256(key=DEK, 域常量‖context)` 的形式存入 v3 头部。
  密钥是每次加密随机的 DEK，因此校验值既不泄露上下文、也无法离线穷举；
- CTXCHECK 处于封装 AAD 覆盖范围内，**改动 CTXCHECK 字段本身**会被判为
  密文篡改（`ErrCiphertextModified`）；
- 解密时先用解出的 DEK 重算校验值比对：**上下文不一致（哪怕只差一个字节）**
  返回 `ErrContextMismatch`，与密文篡改、未知密钥等失败明确区分；
- 校验通过后再做正文 GCM 验签，上下文同时受 HMAC 与 GCM 双重保护；
- `Seal`/`Open` 等价于上下文为空的 `SealWithContext`/`OpenWithContext`；
- v1/v2 历史格式没有上下文绑定能力，其**隐式上下文为空**：对历史密文
  提供非空上下文会被判为 `ErrContextMismatch`。

### 版本演进规则

- **写入**：永远使用最高版本（当前 v3）。
- **读取**：按版本字节分派解析器，v1、v2、v3 可在同一密钥环下任意混合；
  轮换期间历史密文的解密结果不漂移（旧密钥保留为 retired 继续服务解密）。
- **版本即语义**：同一份密文只能按它自己声明的版本理解。任一版本的密文
  字段按另一版本的布局重新拼装后，因两版本 AAD 构造不同，验签必然失败，
  不会被当成合法的另一版本密文打开（v1↔v2↔v3 全部六个方向均如此）。
- **未知版本**：魔数正确但版本号不是 0x01/0x02/0x03 → `ErrUnsupportedVersion`，
  绝不会“按当前格式猜着解析”。
- 魔数错误、截断、长度字段越界、nonce/DEK 零长等 → `ErrMalformedCiphertext`。

### 兼容范围说明

- **v1**：线格式与 AAD 构造保持最初定义，最早写入的 v1 密文可照常读取（只读）。
- **v2**：线格式不变；其 AAD 在引入版本绑定时加固为“用途常量‖0x02‖keyID”
  （v2 尚未对外发布时的预发布加固）。按当前代码写出的 v2 密文可照常读取（只读）。
- **v3**：当前写出版本，新增全头部完整性保护与上下文绑定，向前兼容读取
  v1/v2 历史密文。

## 错误归类（决策表）

| 场景 | 哨兵错误 | 触发阶段 |
|---|---|---|
| 环中无激活密钥时 Seal | `ErrNoActiveKey` | 选密钥 |
| 密文 keyID 在环中不存在 | `ErrUnknownKey` | 选密钥 |
| 密文 keyID 对应密钥已撤销 | `ErrKeyRevoked` | 选密钥 |
| 解密上下文与加密时不一致 | `ErrContextMismatch` | CTXCHECK 比对（v3） |
| 对 v1/v2 历史密文提供非空上下文 | `ErrContextMismatch` | 版本分派后 |
| keyID 被改写成另一个环内密钥 | `ErrCiphertextModified` | GCM 验签（AAD 不匹配） |
| 正文/封装块/标签被篡改 | `ErrCiphertextModified` | GCM 验签 |
| v3 头部任一字段被改动 | `ErrCiphertextModified` | GCM 验签（头部入 AAD） |
| 跨版本重排密文 | `ErrCiphertextModified` | GCM 验签（AAD 含版本绑定） |
| 魔数错误、截断、长度越界 | `ErrMalformedCiphertext` | 格式解析 |
| 版本号无法识别 | `ErrUnsupportedVersion` | 版本分派 |
| 重复 ID、空 ID、密钥非 32 字节 | `ErrDuplicateKeyID` / `ErrInvalidKey` | 入环 |
| 空明文 | `ErrEmptyPlaintext` | Seal |

调用方使用 `errors.Is(err, envelope.ErrXxx)` 即可区分原因。
**安全保证**：解密路径上一旦选不到正确密钥或验签失败立即返回，不尝试其他密钥、
不返回任何明文片段。

## 验证方法

```bash
# 常规单测（日志中含每条用例的输入与判定依据）
go test -v ./...

# 并发轮换 + 竞态检测（并发轮换、持续加解密、v1/v2/v3 混合历史密文巡查）
go test -race -run 'TestConcurrent' -v ./...

# 静态检查
go vet ./...
```

覆盖的关键场景：

- `TestSealOpenRoundtrip` / `TestSealRejectsBadInputs`：基本往返与非法输入；
- `TestContextRoundtrip` / `TestContextMismatch` / `TestContextProtectsEveryByte` /
  `TestContextBoundToCiphertext`：上下文绑定往返、不匹配可区分归类、
  上下文逐字节受保护、跨上下文不可互换；
- `TestContextOnLegacyFormats`：v1/v2 历史密文隐式空上下文语义；
- `TestFormatEvolutionMixedVersions`：v1/v2 历史密文 + v3 新密文混用、未知版本拒绝；
- `TestV3HeaderTamperEveryField` / `TestV3HeaderTamperEveryByte`：v3 头部
  逐字段、逐字节篡改均被拒绝；
- `TestCrossVersionRepackRejected`：v1↔v2↔v3 六方向跨版本重排均被验签拒绝；
- `TestUnknownVersionRejected`：未知版本号明确归类；
- `TestOpenUnknownKey` / `TestOpenRevokedKey`：未知 / 已撤销密钥拒绝且原因可区分；
- `TestRotationKeepsHistoryStable`：多次轮换后历史密文逐条稳定；
- `TestTamperedCiphertext`：正文、DEK 封装块、截断、魔数、空输入；
- `TestTamperedKeyIDCannotFallback`：篡改 keyID 无法借用其他密钥解密；
- `TestConcurrentRotationAndCrypto` / `TestConcurrentRotationMixedFormats`：
  `-race` 下并发轮换/加解密，新旧格式混合历史密文解密结果不漂移。

## 文件组织

| 文件 | 职责 |
|---|---|
| `errors.go` | 全部可区分哨兵错误 |
| `keyring.go` | 并发安全多版本密钥环（active/retired/revoked、轮换、撤销） |
| `format.go` | v1/v2/v3 线格式的严格解析与序列化 |
| `envelope.go` | 信封加解密主流程（AES-256-GCM、随机 DEK、版本感知 AAD、上下文绑定） |
| `envelope_test.go` / `keyring_test.go` | 基本往返、轮换、篡改、并发回归用例 |
| `context_test.go` | 加密上下文绑定语义用例 |
| `format_v3_test.go` | v3 头部完整性、跨版本重排、未知版本、混合格式并发用例 |
