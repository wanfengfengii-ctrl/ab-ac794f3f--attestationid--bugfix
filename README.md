# 卫星载荷配置签名接纳网关 (Satellite Payload Attestation Gateway)

在向卫星载荷下发配置前，确认：

1. 供应商对配置载荷的 **Ed25519 签名有效**；
2. 提交的**代次（generation）承接当前已接纳代次**，防止重放、回退与并发分叉；
3. 只有随部署声明的设备公钥能为对应设备背书。

零第三方依赖，仅使用 Node.js ≥ 20 内置模块（`node:crypto` 原生 Ed25519）。

---

## API

### `POST /api/attestations`

请求体（JSON）：

| 字段 | 说明 |
| --- | --- |
| `attestationId` | 本次签名接纳编号（字符串），**全局唯一**幂等身份，跨所有设备共用；同编号重试按幂等处理 |
| `keyId` | 签名所用密钥在部署清单中的标识 |
| `payloadBase64` | 载荷的 base64；**签名对象是其解码后的原始字节** |
| `signatureBase64` | 对载荷原始字节的 Ed25519 签名（64 字节）的 base64 |

载荷必须是 **UTF-8 JSON**，且包含：

```json
{
  "deviceId": "SAT-A01",
  "generation": 2,
  "previousGeneration": 1,
  "configSha256": "小写 64 位配置 SHA-256"
}
```

接纳规则：

- 每台设备**首次**提交的 `previousGeneration` 必须为 `0`；
- 之后 `previousGeneration` 必须**等于当前已接纳代次**，且新 `generation` 严格更大；
- **同编号 + 同内容**重试：`attestationId` 是**跨所有设备全局唯一**的幂等身份：
  - 同一设备以**完全相同的设备、密钥、代际字段、配置摘要及已签名载荷字节**重试，
    返回原结果（`200`, `replayed: true`），不改变状态；
  - 同编号但设备、密钥、代际/配置字段或**已签名载荷原始字节**（含额外 JSON 字段、
    不同序列化字节）有任何差异，无论来自本设备还是另一台设备，均返回 `409`
    且**绝不为任何设备创建/推进 head**；
- **过期/分叉前代**、**回退/同代异内容**：均返回 `409` 且**绝不推进设备状态**；
- 未知 `keyId` → `401 UNKNOWN_KEY`；签名错误 → `401 INVALID_SIGNATURE`；
  密钥与设备绑定不符 → `403 KEY_DEVICE_MISMATCH`。

成功响应：`201`（重试为 `200`）

```json
{
  "replayed": false,
  "accepted": { "attestationId": "...", "deviceId": "SAT-A01", "generation": 2, "payloadSha256": "...", "...": "..." },
  "head": { "deviceId": "SAT-A01", "generation": 2, "configSha256": "...", "configSize": 312 }
}
```

### `GET /api/devices/{deviceId}/head`

返回该设备**唯一**已接纳代次与配置摘要；重启后结果不变（从磁盘日志重建）。
未知设备返回 `404 DEVICE_NOT_FOUND`。

### `GET /health`（另有别名 `/healthz`）

```json
{ "status": "ok", "uptimeSeconds": 3, "timestamp": "..." }
```

### 稳定错误码

所有错误响应形如：

```json
{ "error": { "code": "PREDECESSOR_MISMATCH", "message": "...", "details": { } } }
```

| HTTP | code | 场景 |
| --- | --- | --- |
| 400 | `INVALID_REQUEST` / `INVALID_PAYLOAD` | 信封/载荷格式、base64、UTF-8、字段非法 |
| 401 | `UNKNOWN_KEY` | keyId 未在部署清单声明 |
| 401 | `INVALID_SIGNATURE` | Ed25519 验签失败（且不推进状态） |
| 403 | `KEY_DEVICE_MISMATCH` | 密钥不属于该设备 |
| 404 | `DEVICE_NOT_FOUND` / `ROUTE_NOT_FOUND` | 无已接纳代次 / 路径不存在 |
| 409 | `GENERATION_CONFLICT` | 同编号（含跨设备/不同已签名字节）异内容、同代异内容 |
| 409 | `PREDECESSOR_MISMATCH` | 前代 ≠ 当前已接纳代次（过期/分叉） |
| 409 | `GENERATION_NOT_ADVANCED` | 回退到更旧代次 |

---

## 持久化与并发

- 每台设备一个**仅追加日志** `data/configs/<deviceId>.log`，每行一个已接纳记录；
  另有一个**全局**仅追加索引 `data/attestations.log`，每行记录同一个已接纳信封，
  它是 `attestationId` 的全局唯一判重集——同一编号只能在一台设备上被接纳一次。
  写入在应答前对两个文件依次 `fsync`（先设备日志、后全局索引），重启时先回放索引、
  再逐设备回放并交叉校验链，重建唯一 head；崩溃在两次写入之间留下的缺失索引行会从
  设备日志自愈，崩溃导致的半行尾记录会被安全截断。
- 同设备的「检查—判定」经每设备互斥链串行化，最终的「全局编号判重—双日志提交」再经
  一个进程级互斥串行化：同一编号的并发请求（**即使来自不同设备**）恰好一个成功，
  另一个得到稳定 409，绝不分叉、绝不在败方设备上创建 head。
- 每条已接纳信封持久化 `payloadSha256`（已签名载荷原始字节的 SHA-256），幂等重放要求
  设备、密钥、代际字段、配置摘要与已签名载荷字节全部一致。

## 设备公钥（随部署声明）

`config/device-keys.json`：

```json
{
  "keys": { "sat-a01-ed25519-1": "<base64 32 字节裸公钥 | PEM | JWK>" },
  "devices": { "SAT-A01": { "keyId": "sat-a01-ed25519-1", "publicKey": "..." } }
}
```

生产环境应以 KMS/HSM 中生成的公钥替换示例清单。重新生成示例清单及仅测试用私钥夹具：

```bash
node tools/gen-keys.mjs
```

## 本地运行（无需 Docker）

```bash
node tools/gen-keys.mjs          # 首次：生成 config/device-keys.json
npm test                         # 40 个单元/集成测试
npm run check                    # 语法、清单与模块图构建检查
npm run smoke                    # 端到端签名接纳冒烟（含并发竞争与重启恢复）
npm start                        # 启动 API（PORT 默认 8080）
```

## Docker / Docker Compose

宿主机端口完全由 `APP_PORT` 控制（见 `.env`，默认 8080）：

```bash
APP_PORT=9090 docker compose up -d --build api
curl -fsS http://localhost:9090/health
```

一次性验证服务 `verify` —— 依次运行**代码测试、构建检查、签名接纳冒烟**，
完成后自行退出，并用退出码汇总结果（0 = 全部通过）：

```bash
docker compose run --rm verify
# 或构建后随编排一次性执行：
docker compose up --build verify
```

## 目录结构

```
src/        服务器、HTTP、接纳逻辑、签名校验、持久化
tools/      verify 编排器、冒烟、构建检查、密钥生成、签名辅助
test/       node:test 测试（存储、接纳规则、HTTP）
config/     随部署声明的设备公钥清单
Dockerfile / docker-compose.yml
```
