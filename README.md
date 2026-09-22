# envelope-keyring-go

本地信封加密（Envelope Encryption）与多版本密钥轮换库。用内存中的本地
密钥环模拟云端 KMS：每条数据由随机数据密钥（DEK）加密，DEK 再由密钥环中
当前激活的主密钥（KEK）封装；密文自描述所用 KEK 标识与格式版本。

- 新数据始终由**当前激活密钥**封装
- 解密严格按密文携带的密钥标识选密钥，**永不回退**到其他密钥
- 轮换只追加新版本密钥，旧密钥保留用于解密历史密文
- 密文格式支持版本演进：新写 V2，历史 V1 继续可读，未知版本明确拒绝
- 所有失败均可通过 `errors.Is` 归类，且不返回明文、不泄漏密钥材料
- 密钥环读写使用 `sync.RWMutex`，轮换可与并发加解密安全共存

## 安装与快速上手

```go
kr := envelope.NewKeyring()
_ = kr.AddKey("kek-1", key32, true)          // 登记并激活
c := envelope.NewEnvelopeCipher(kr)

ct, _ := c.Encrypt([]byte("hello"), []byte("aad"))  // 用激活密钥封装
pt, err := c.Decrypt(ct, []byte("aad"))             // 按密文标识选密钥

_ = kr.Rotate("kek-2", key32)               // 轮换：kek-1 保留可解密
pt, _ = c.Decrypt(ct, []byte("aad"))         // 历史密文仍可解出
```

## 密码学结构

- KEK / DEK 均为 AES-256；两层加密都使用 AES-256-GCM（随机 12 字节 nonce）。
- `Encrypt` 每次生成新的随机 DEK 与两个独立 nonce（封装 nonce、数据 nonce）。
- 封装层 AAD 绑定 `"envelope-wrap-v" + 版本字节 + keyID + 业务 AAD`，
  防止跨密钥、跨格式重放；数据层 AAD 带 `"envelope-data-v1"` 域分隔前缀。
- DEK 在用完后于内存中清零；KEK 材料以拷贝方式存入/取出密钥环，外部无法
  通过指针改动内部状态；密钥材料不出现在密文头（仅 keyID 为明文）或错误信息中。

## 密文格式

所有版本共享魔数 `ENVK`，第 5 字节为版本号：

```
V1: "ENVK" | 0x01 | idLen uint8   | keyID | nonce[24] | wLen uint16BE | wrappedDEK | ciphertext
V2: "ENVK" | 0x02 | idLen uint16BE | keyID | nonceLen uint8(=24) | nonce | wLen uint16BE | wrappedDEK | ciphertext
```

- `nonce` 为 `封装nonce(12) || 数据nonce(12)`，共 24 字节。
- `wrappedDEK` 是 GCM 封装后的 DEK（内含 16 字节认证标签）。
- `ciphertext` 是 `密文 || 16 字节 GCM 标签`。

### V1 → V2 演进语义

- V1 的 keyID 长度用 1 字节表示（上限 255），V2 改为 2 字节（上限 65535），
  且 V2 显式携带 nonce 长度字段，为将来扩展预留空间。
- 新写入一律为 V2（`currentFormat`）。
- 读取时按版本字节分流解析，V1、V2 可在同一密钥环下混合使用。
- 版本字节不是 1 或 2 时，返回 `ErrUnsupportedVersion`，**绝不**按当前格式猜测解析。

## 密钥轮换语义

| 操作 | 语义 |
| --- | --- |
| `AddKey(id, mat, activate)` | 登记密钥；标识唯一，材料必须为 32 字节；可同时置为激活 |
| `Rotate(id, mat)` | 追加新密钥并激活；旧激活密钥转为非激活但**仍可解密历史密文** |
| `DisableKey(id)` | 显式停用历史密钥：标识可识别，但解密返回 `ErrKeyDisabled`；不允许停用当前激活密钥（必须先轮换） |
| `ActiveKey()` | 获取当前激活密钥快照（一次调用内不受并发轮换影响） |
| `KeyFor(id)` | 解密路径使用：未知标识 → `ErrUnknownKey`；已停用 → `ErrKeyDisabled` |

轮换是「追加而非替换」：因为密钥选择只依据密文自带的 keyID，
轮换前用旧 KEK 封装的密文在轮换后仍稳定解出同一明文。

## 错误归类（可区分、可解释）

所有错误均为 `*envelope.Error`，可用 `errors.Is` 命中哨兵原因，并携带 keyID
与可读的判定细节：

| 哨兵错误 | 触发情形 |
| --- | --- |
| `ErrNoActiveKey` | 加密时密钥环无激活密钥 |
| `ErrUnknownKey` | 密文 keyID 在密钥环中不存在（绝不尝试其他密钥） |
| `ErrKeyDisabled` | keyID 存在但已被显式停用，或试图停用激活密钥 |
| `ErrInvalidFormat` | 密文过短、魔数错误、长度字段越界、空载荷等结构非法输入 |
| `ErrUnsupportedVersion` | 版本字节无法识别（拒绝按当前格式误解析） |
| `ErrCiphertextTampered` | 结构合法但任一层 GCM 认证失败（密文/封装/nonce/AAD 被改或不符） |

解析失败与认证失败严格区分：先做结构校验（`ErrInvalidFormat` /
`ErrUnsupportedVersion`），再查密钥（`ErrUnknownKey` / `ErrKeyDisabled`），
最后做两层密码学认证（失败一律 `ErrCiphertextTampered`），任一步失败都不会
输出明文。

## 验证方法

```bash
go build ./...
go vet ./...
go test -race -v ./...
```

测试覆盖：

- V1/V2 混合读写、长 keyID 的版本差异、未知版本拒绝
- 轮换前后历史密文解密结果稳定、新密文切换到新密钥
- 30 次轮换与加解密 goroutine 并发共存（`-race`）
- 未知密钥、已停用密钥、篡改密文载荷/封装段/AAD、各种截断与非法输入
- 每个用例通过 `t.Logf` 打印输入与归类的判定依据

## 范围说明

密钥材料由调用方提供，密钥环保存在进程内存中，定位是本地模拟与教学用途；
生产环境应将 KEK 置于 HSM/KMS，并配合持久化、访问控制与密钥材料销毁流程。
