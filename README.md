# Gin File Handler - 文件上传服务器

一个基于 Gin 框架的文件上传和管理服务器，支持 RSA 签名验证的设备认证机制。
go gin支持多客户端连接 ，每个客户端连接都需要进行认证，认证通过后才能进行文件上传、下载、指令传输等操作。

## 功能特性

- 🔐 RSA 签名验证的设备认证
- 📁 文件上传和下载
- 🖥️ Web 管理界面
- 📱 设备管理
- 🔧 指令传输

## 路由说明

### 静态文件服务
- `GET /customer/static/*` - 静态文件服务，提供 CSS、JS、图片等静态资源

### 管理页面
- `GET /customer/management` - 访问 Web 管理界面

### 设备认证相关
- `POST /customer/auth/add` - 注册新设备（无需认证）

### 设备管理（需要认证）
- `GET /customer/device/` - 获取所有设备列表
- `PUT /customer/device/` - 更新设备信息

### 文件操作（需要认证）
- `POST /customer/upload/file` - 上传文件
- `GET /customer/download/file/:filename` - 下载文件

### 指令传输（需要认证）
- `POST /customer/command/execute` - 执行指令

## 如何访问静态页面

### 1. 启动服务器
```bash
go run main.go
```
服务器默认运行在 `http://localhost:8080`

### 2. 访问管理页面
在浏览器中访问：
```
http://localhost:8080/customer/static/management.html
```

### 3. 访问静态资源
静态文件可以通过以下路径访问：
```
http://localhost:8080/customer/static/文件名
```

例如：
- `http://localhost:8080/customer/static/public_key.pem` - RSA 公钥文件
- `http://localhost:8080/customer/static/style.css` - 样式文件（如果存在）

## RSA 认证验证机制

### 认证原理
本系统使用 RSA 加密算法进行设备认证，确保只有授权设备才能访问受保护的 API。

### 认证流程
1. **设备注册**：首先通过 `/customer/auth/add` 注册设备
2. **生成签名**：客户端使用 RSA 公钥生成请求签名
3. **发送请求**：在请求头中包含认证信息
4. **服务器验证**：服务器使用私钥验证签名的有效性

### 认证头格式
需要在请求头中包含以下字段：
```
LY-Device-ID: 设备ID
LY-Timestamp: 时间戳
LY-Signature: RSA签名（Base64编码）
```

### 签名生成算法
1. 创建 payload：`设备ID|时间戳`（字段按字母顺序排序）
2. 使用 RSA-OAEP 加密 payload
3. 计算加密数据的 SHA256 哈希
4. 使用 RSA-OAEP 加密哈希值作为签名
5. 将签名进行 Base64 编码

## 验证示例

### 1. Python 客户端示例

```python
import requests
import time
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def load_public_key():
    """加载RSA公钥"""
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def generate_auth_headers(device_id, public_key):
    """生成认证头"""
    timestamp = int(time.time())
    
    # 创建payload
    fields = [device_id, str(timestamp)]
    fields.sort()
    payload = '|'.join(fields)
    
    # 使用RSA-OAEP加密payload
    encrypted_payload = public_key.encrypt(
        payload.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 计算SHA256哈希
    hash_value = hashlib.sha256(encrypted_payload).digest()
    
    # 使用RSA-OAEP加密哈希值作为签名
    signature = public_key.encrypt(
        hash_value,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 转换为base64
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    return {
        'LY-Device-ID': device_id,
        'LY-Timestamp': str(timestamp),
        'LY-Signature': signature_b64,
        'Content-Type': 'application/json'
    }

# 使用示例
public_key = load_public_key()
headers = generate_auth_headers('test_device_001', public_key)

# 获取设备列表
response = requests.get('http://localhost:8080/customer/device/', headers=headers)
print(f"状态码: {response.status_code}")
print(f"响应: {response.json()}")
```

### 2. JavaScript 客户端示例（Web 管理页面）

```javascript
// 使用 node-forge 库进行 RSA 加密
async function generateAuthHeaders() {
    const timestamp = Math.floor(Date.now() / 1000);
    const deviceId = 'management_device_001';
    
    // 创建payload
    const fields = [deviceId, timestamp.toString()];
    fields.sort();
    const payload = fields.join('|');
    
    // 使用RSA-OAEP加密payload
    const encryptedPayload = publicKey.encrypt(payload, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: { md: forge.md.sha256.create() }
    });
    
    // 计算SHA256哈希
    const md = forge.md.sha256.create();
    md.update(encryptedPayload);
    const hash = md.digest();
    
    // 使用RSA-OAEP加密哈希值作为签名
    const signature = publicKey.encrypt(hash.getBytes(), 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: { md: forge.md.sha256.create() }
    });
    
    // 转换为base64
    const signatureB64 = forge.util.encode64(signature);
    
    return {
        'LY-Device-ID': deviceId,
        'LY-Timestamp': timestamp.toString(),
        'LY-Signature': signatureB64,
        'Content-Type': 'application/json'
    };
}

// 获取设备列表
async function fetchDevices() {
    const headers = await generateAuthHeaders();
    const response = await fetch('/customer/device/', {
        method: 'GET',
        headers: headers
    });
    
    if (response.ok) {
        const data = await response.json();
        console.log('设备列表:', data);
    } else {
        console.error('请求失败:', response.status);
    }
}
```

### 3. 设备注册示例

```bash
# 注册新设备
curl -X POST http://localhost:8080/customer/auth/add \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "test_device_001",
    "title": "测试设备",
    "enabled": true
  }'
```

### 4. 文件上传示例

```python
# 文件上传（需要认证）
def upload_file(file_path, device_id, public_key):
    headers = generate_auth_headers(device_id, public_key)
    
    with open(file_path, 'rb') as f:
        files = {'file': f}
        response = requests.post(
            'http://localhost:8080/customer/upload/file',
            files=files,
            headers=headers
        )
    
    return response.json()

# 使用示例
result = upload_file('test.txt', 'test_device_001', public_key)
print(f"上传结果: {result}")
```

## 安全特性

1. **时间戳验证**：防止重放攻击，时间戳有效期为 180 秒
2. **RSA 加密**：使用 RSA-OAEP 填充模式确保安全性
3. **设备白名单**：只有注册的设备才能访问受保护的 API
4. **签名验证**：每个请求都需要有效的 RSA 签名

## 项目结构

```
gin-hander/
├── main.go                 # 主程序入口
├── conf/                   # 配置文件
├── pkg/
│   ├── api/
│   │   └── customer.go     # 客户端 API 路由
│   ├── auth/
│   │   ├── token.go        # 设备认证 Token
│   │   └── validator.go    # 设备验证器
│   ├── model/              # 数据模型
│   └── rsautils/           # RSA 工具函数
├── static/
│   ├── management.html     # Web 管理界面
│   └── public_key.pem      # RSA 公钥文件
├── tests/                  # 测试文件
├── private_key.pem         # RSA 私钥文件
└── README.md              # 项目说明
```

## 运行要求

- Go 1.19+
- SQLite3（用于设备数据存储）
- RSA 密钥对（private_key.pem 和 public_key.pem）

## 快速开始

1. 克隆项目并安装依赖：
```bash
go mod tidy
```

2. 生成 RSA 密钥对（如果不存在）：
```bash
# 生成私钥
openssl genrsa -out private_key.pem 2048

# 生成公钥
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

3. 启动服务器：
```bash
go run main.go
```

4. 访问管理界面：
```
http://localhost:8080/customer/management
```

## 注意事项

- 确保 `private_key.pem` 和 `public_key.pem` 文件存在于项目根目录
- 管理页面使用固定的设备 ID：`management_device_001` 实际上不能这样作为验证，有先经过登录程序
- 所有受保护的 API 都需要有效的 RSA 签名认证
- 时间戳验证有 180 秒的有效期，确保客户端时间同步