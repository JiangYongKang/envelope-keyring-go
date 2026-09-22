# envelope-keyring-go

基于**本地多版本密钥环**的信封加密（Envelope Encryption）与**密钥轮换**模拟库。
密钥材料仅存在于内存，重点演示：

- 新数据始终由**当前激活密钥**封装；解密严格按**密文自携带的密钥标识**选密钥；
- 轮换时**保留历史密钥**用于解密，轮换与并发加解密安全共存；
- 密文格式支持**版本演进**（v1/v2 可在同一密钥环下混用），未知版本明确拒绝；
- 所有失败均归类为**可区分的哨兵错误**，绝不回退到错误密钥、绝不静默返回明文。

## 快速开始

```go
ring := envelope.NewKeyRing()
_ = ring.AddKey("k1", keyBytes32, true)          // true = 立即激活
svc := envelope.NewEnvelopeService(ring)

ct, err := svc.Seal([]byte("敏感数据"))           // 当前激活密钥 + 当前格式(v2)
pt, err := svc.Open(ct)                          // 按密文内 keyID 选密钥

_ = ring.Rotate("k2", newKeyBytes32)             // 轮换：k2 激活，k1 转 retired
pt2, _ := svc.Open(ct)                           // 旧密文仍可由 k1(retired) 解密
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

### v2（`0x02`，当前写出版本）

```
MAGIC(4)="EKR1" | VER(1)=0x02 | FLAGS(1)
| KEYIDLEN(2,BE) | KEYID(…)                     # 密钥标识长度扩展到 64KiB
| DEKLEN(2,BE) | ENC_DEK(…)                     # wrapNonce(12) || GCM(KEK, DEK)
| NONCELEN(1) | NONCE(…)                        # nonce 长度自描述
| TIMESTAMP(8,BE, Unix 秒)                      # 新增封装时间戳
| CIPHERTEXT+TAG(…)                             # AES-256-GCM
```

### 信封结构（两版本相同的密码学结构）

1. 每次 Seal 生成随机 32 字节数据密钥 `DEK`；
2. `ENC_DEK = wrapNonce(12) || AES-GCM-Seal(KEK=激活密钥, DEK, AAD=用途常量‖keyID)`；
3. `CIPHERTEXT = AES-GCM-Seal(DEK, plaintext, AAD=用途常量‖keyID)`。

两层 GCM 的 AAD 都绑定密钥标识与用途，因此：
- 把密文的 keyID 改成**另一个环内密钥** → 用该密钥解封装时标签校验失败；
- 把密文搬到别的上下文 / 用错密钥 → 同样验签失败；
- 任何明文字节、nonce、封装块被翻转 → `ErrCiphertextModified`。

### 版本演进规则

- **写入**：永远使用最高版本（当前 v2）。
- **读取**：按版本字节分派解析器，v1 与 v2 可在同一密钥环下任意混合。
- **未知版本**：魔数正确但版本号不是 0x01/0x02 → `ErrUnsupportedVersion`，
  绝不会“按当前格式猜着解析”。
- 魔数错误、截断、长度字段越界、nonce/DEK 零长等 → `ErrMalformedCiphertext`。

## 错误归类（决策表）

| 场景 | 哨兵错误 | 触发阶段 |
|---|---|---|
| 环中无激活密钥时 Seal | `ErrNoActiveKey` | 选密钥 |
| 密文 keyID 在环中不存在 | `ErrUnknownKey` | 选密钥 |
| 密文 keyID 对应密钥已撤销 | `ErrKeyRevoked` | 选密钥 |
| keyID 被改写成另一个环内密钥 | `ErrCiphertextModified` | GCM 验签（AAD 不匹配） |
| 正文/封装块/标签被篡改 | `ErrCiphertextModified` | GCM 验签 |
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

# 并发轮换 + 竞态检测（100 次并发轮换、8 个持续加解密协程、历史密文巡查）
go test -race -run TestConcurrentRotationAndCrypto -v ./...

# 静态检查
go vet ./...
```

覆盖的关键场景：

- `TestSealOpenRoundtrip` / `TestSealRejectsBadInputs`：基本往返与非法输入；
- `TestFormatEvolutionV1AndV2Mix`：v1 历史密文 + v2 新密文混用、未知版本拒绝；
- `TestOpenUnknownKey` / `TestOpenRevokedKey`：未知 / 已撤销密钥拒绝且原因可区分；
- `TestRotationKeepsHistoryStable`：多次轮换后历史密文逐条稳定；
- `TestTamperedCiphertext`：正文、DEK 封装块、截断、魔数、空输入；
- `TestTamperedKeyIDCannotFallback`：篡改 keyID 无法借用其他密钥解密；
- `TestConcurrentRotationAndCrypto`：`-race` 下并发轮换/加解密与历史密文稳定性。

## 文件组织

| 文件 | 职责 |
|---|---|
| `errors.go` | 全部可区分哨兵错误 |
| `keyring.go` | 并发安全多版本密钥环（active/retired/revoked、轮换、撤销） |
| `format.go` | v1/v2 线格式的严格解析与序列化 |
| `envelope.go` | 信封加解密主流程（AES-256-GCM、随机 DEK、AAD 绑定） |
