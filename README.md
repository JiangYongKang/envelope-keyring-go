# envelope-keyring-go

基于**本地多版本密钥环**的信封加密（Envelope Encryption）与**密钥轮换**模拟库。
密钥材料仅存在于内存，重点演示：

- 新数据始终由**当前激活密钥**封装；解密严格按**密文自携带的密钥标识**选密钥；
- 轮换时**保留历史密钥**用于解密，轮换与并发加解密安全共存；
- 密文格式支持**版本演进**（v1/v2/v3 可在同一密钥环下混用），未知版本明确拒绝；
- **v3**：调用方**上下文标识**（租户/用途等）密码学绑定，上下文不对得到独立的
  `ErrContextMismatch`；**头部每一个字段逐字节受完整性保护**；
- 每个格式版本使用**独立 AAD 域**，跨版本重拼密文无法通过验签；
- 所有失败均归类为**可区分的哨兵错误**，绝不回退到错误密钥、绝不静默返回明文。

## 快速开始

```go
ring := envelope.NewKeyRing()
_ = ring.AddKey("k1", keyBytes32, true)          // true = 立即激活
svc := envelope.NewEnvelopeService(ring)

// 带上下文的封装（推荐）：同一段上下文必须在解密时原样提供。
ct, err := svc.SealWithContext([]byte("敏感数据"), []byte("tenant-42/billing"))
pt, err := svc.OpenWithContext(ct, []byte("tenant-42/billing"))

// 无上下文 API 等价于空上下文绑定，新密文默认仍写当前格式（v3）。
ct2, _ := svc.Seal([]byte("另一段数据"))
pt2, _ := svc.Open(ct2)

_ = ring.Rotate("k2", newKeyBytes32)             // 轮换：k2 激活，k1 转 retired
_, _ = svc.OpenWithContext(ct, []byte("tenant-42/billing")) // 旧密文仍可由 k1 解密
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

### v2（`0x02`，历史写出版本，仍可读）

```
MAGIC(4)="EKR1" | VER(1)=0x02 | FLAGS(1)
| KEYIDLEN(2,BE) | KEYID(…)                     # 密钥标识长度扩展到 64KiB
| DEKLEN(2,BE) | ENC_DEK(…)                     # wrapNonce(12) || GCM(KEK, DEK)
| NONCELEN(1) | NONCE(…)                        # nonce 长度自描述
| TIMESTAMP(8,BE, Unix 秒)                      # 封装时间戳
| CIPHERTEXT+TAG(…)                             # AES-256-GCM
```

### v3（`0x03`，当前写出版本，默认）

```
MAGIC(4)="EKR1" | VER(1)=0x03 | FLAGS(1)
| KEYIDLEN(2,BE) | KEYID(…)
| DEKLEN(2,BE) | ENC_DEK(…)                     # wrapNonce(12) || GCM(KEK, DEK)
| NONCELEN(2,BE) | NONCE(…)                     # nonce 长度扩展到 64KiB
| CTXLEN(2,BE) | CTX(…)                         # 调用方上下文标识（可为空）
| TIMESTAMP(8,BE, Unix 秒)
| CIPHERTEXT+TAG(…)                             # AES-256-GCM
```

其中 **HEADER = 从 MAGIC 到 TIMESTAMP 的全部字节**（不含 CIPHERTEXT）。

v3 相对 v2 的关键变化：

1. **上下文绑定（CTX）**：任意调用方提供的字节串（租户/用途等），随头部一起存储；
2. **头部全字段完整性**：正文 GCM 直接以完整 HEADER 作为 AAD，头部里
   `MAGIC/VER/FLAGS/KEYIDLEN/KEYID/DEKLEN/ENC_DEK/NONCELEN/NONCE/CTXLEN/CTX/TIMESTAMP`
   中的**任何一个字节**被改动，正文标签都不可能通过，解密被直接拒绝；
3. nonce 长度字段扩为 2 字节。

### 信封结构与 AAD（各版本独立域）

每次 Seal 生成随机 32 字节 DEK；两层 AES-256-GCM 的 AAD 按版本隔离：

| 版本 | DEK 封装层 AAD | 正文层 AAD |
|---|---|---|
| v1 | `dek-wrap/v1 ‖ 0 ‖ keyID`（历史固定，永不改变） | `payload/v1 ‖ 0 ‖ keyID` |
| v2 | `dek-wrap/v2 ‖ 0 ‖ keyID` | `payload/v2 ‖ 0 ‖ keyID` |
| v3 | `dek-wrap/v3 ‖ KEYIDLEN(2) ‖ keyID ‖ CTXLEN(2) ‖ CTX` | **完整 HEADER 原文** |

由此得到：

- 把密文的 keyID 改成**另一个环内密钥** → 用该密钥解封装时标签校验失败；
- **v3 头部任何字段被翻转/重写**（含版本号、魔数、长度字段、时间戳、上下文）
  → 正文验签失败（`ErrCiphertextModified`），不存在“改了某些头部还能打开”的字段；
- 把一种版本密文的字段**按另一版本布局重拼**（v1↔v2、v2↔v3）→ AAD 域不同，
  即使能解析也必然验签失败；
- 任何明文字节、nonce、封装块被翻转 → `ErrCiphertextModified`。

> 兼容性说明：v1 的 AAD 域被永久冻结，保证最初写出去的 v1 密文解密结论不漂移；
> v2 使用独立 `…/v2` 域与 v1 区分。三代密文在同一密钥环下可任意混合读取。

## 上下文绑定语义（v3）

- `SealWithContext(pt, ctx)` 将 `ctx` 绑定进密文；`OpenWithContext(ct, ctx)`
  必须提供**逐字节相同**的 `ctx`（nil 与空切片等价）。
- 上下文不匹配（密文完整、只是调用方给错）→ **`ErrContextMismatch`**，
  与 `ErrCiphertextModified`（篡改/损坏）明确区分，且该判定**先于密钥查找**，
  结论不受密钥是否存在、是否撤销影响。
- 直接改动密文头部里的 CTX 字节：
  - 仍提供原 ctx → 头部声明值与提供值不符 → `ErrContextMismatch`；
  - 提供与被改头部一致的 ctx 试图蒙混比对 → GCM 标签仍认证原上下文
    → `ErrCiphertextModified`。即上下文每个字都受完整性保护。
- v1/v2 密文没有上下文字段：只能以**空上下文**打开（`Open` 或传 nil）；
  带非空上下文打开历史密文返回 `ErrContextMismatch`。
- ctx 上限 65535 字节，超出在封装阶段返回 `ErrContextTooLarge`。

### 版本演进规则

- **写入**：永远使用最高版本（当前 v3），默认携带空上下文；需要租户/用途隔离时
  使用 `SealWithContext`。
- **读取**：按版本字节分派解析器与 AAD 域，v1/v2/v3 可在同一密钥环下任意混合。
- **未知版本**：魔数正确但版本号不是 0x01/0x02/0x03 → `ErrUnsupportedVersion`，
  绝不会“按当前格式猜着解析”。
- 密文**只按自己声明的版本**被理解；跨版本重排见上文 AAD 表。
- 魔数错误、截断、长度字段越界、nonce/DEK/keyID 零长等 → `ErrMalformedCiphertext`。

## 错误归类（决策表）

| 场景 | 哨兵错误 | 触发阶段 |
|---|---|---|
| 环中无激活密钥时 Seal | `ErrNoActiveKey` | 选密钥 |
| 密文 keyID 在环中不存在 | `ErrUnknownKey` | 选密钥 |
| 密文 keyID 对应密钥已撤销 | `ErrKeyRevoked` | 选密钥 |
| 解密提供的上下文与密文绑定上下文不一致 | `ErrContextMismatch` | 上下文比对（先于密钥查找） |
| 上下文超过 64KiB | `ErrContextTooLarge` | Seal 入参校验 |
| keyID 被改写成另一个环内密钥 | `ErrCiphertextModified` | GCM 验签（AAD 不匹配） |
| v3 头部任意字段/字节被篡改（含 CTX、版本、时间戳） | `ErrCiphertextModified` | GCM 验签（HEADER 是 AAD） |
| 正文/封装块/标签被篡改 | `ErrCiphertextModified` | GCM 验签 |
| 跨版本重排密文 | `ErrCiphertextModified` / `ErrMalformedCiphertext` | 版本专属 AAD / 解析 |
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

# 并发轮换 + 竞态检测（含三代格式混用与上下文绑定）
go test -race -v ./...

# 仅并发场景
go test -race -run 'TestConcurrentRotation' -v ./...

# 静态检查
go vet ./...
```

覆盖的关键场景：

- `TestSealOpenRoundtrip` / `TestSealRejectsBadInputs`：基本往返（默认 v3）与非法输入；
- `TestContextBindingRoundtrip` / `TestContextMismatch`：上下文往返、逐字节不一致、
  空/非空语义；
- `TestContextTamperedOnWire`：线上 CTX 被改的两条拒绝路径
  （`ErrContextMismatch` 与 `ErrCiphertextModified`）；
- `TestContextTooLarge`：上下文超长在封装前拒绝；
- `TestV3EveryHeaderFieldIsAuthenticated`：v3 头部**每个字段**（MAGIC/VER/FLAGS/
  KEYIDLEN/KEYID/DEKLEN/ENC_DEK/NONCELEN/NONCE/CTXLEN/CTX/TIMESTAMP）翻转后均无法打开；
- `TestV3HeaderByteSweep`：对头部**每一个字节**逐一翻转，无一可解密；
- `TestFormatEvolutionV1V2V3Mix`：v1/v2 历史密文 + v3 新密文混用、历史密文不接受上下文；
- `TestCrossVersionRepackRejected`：v1↔v2、v2↔v3 四种跨版本布局重排全部拒绝；
- `TestUnknownVersionRejected`：0x00/0x04/0x7F/0xFE 等未知版本明确拒绝；
- `TestV3TamperedKeyIDCannotFallback`：v3 篡改 keyID 无法借用其他密钥；
- `TestOpenUnknownKey` / `TestOpenRevokedKey`：未知 / 已撤销密钥拒绝且原因可区分；
- `TestRotationKeepsHistoryStable`：多次轮换后历史密文逐条稳定；
- `TestTamperedCiphertext` / `TestTamperedKeyIDCannotFallback`：正文、DEK 封装块、
  截断、魔数、空输入与 v2 keyID 改写；
- `TestConcurrentRotationAndCrypto`：`-race` 下并发轮换/加解密与历史密文稳定性；
- `TestConcurrentRotationMixedFormats`：`-race` 下并发轮换、v3 实时加解密（交替上下文）
  与 v1/v2/v3 三代历史密文持续巡查，明文不漂移。

## 文件组织

| 文件 | 职责 |
|---|---|
| `errors.go` | 全部可区分哨兵错误（含 `ErrContextMismatch`/`ErrContextTooLarge`） |
| `keyring.go` | 并发安全多版本密钥环（active/retired/revoked、轮换、撤销） |
| `format.go` | v1/v2/v3 线格式的严格解析与序列化（v3 含 CTX 与完整头部区域） |
| `envelope.go` | 信封加解密主流程（AES-256-GCM、随机 DEK、按版本分派 AAD、上下文绑定） |
| `context_test.go` | 上下文绑定：往返、不匹配、线上篡改、空语义、超长 |
| `v3header_test.go` | v3 头部逐字段/逐字节完整性 |
| `version_test.go` | 跨版本重排、未知版本、v3 keyID 防回退 |
| `concurrent_mix_test.go` | 并发轮换下三代格式混用 |
