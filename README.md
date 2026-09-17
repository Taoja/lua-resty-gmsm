# lua-resty-gmsm

基于OpenSSL的国密实现，以下环境已测试通过

- [x] OpenSSL1.1.1w + OpenResty1.25.3.2
- [x] OpenSSL3.0.22 + OpenResty1.25.3.2
- [x] OpenSSL3.6.4 + OpenResty1.25.3.2
- [x] OpenSSL4.0.2 + OpenResty1.31.1.1

当前支持sm2、sm3、sm4

其中sm4支持ecb、cbc、cfb、ofb、ctr、gcm（openssl3.6以上支持），并且都只支持pkcs7补位

SM2 公钥、私钥和密文的外部输入输出统一使用ASN.1 der Base64 文本格式，密文固定使用C1C3C2格式。

## 使用方法

推荐安装openSSL3.6+版本，并使用openresty动态链接至openSSL3.6+版本。

### 安装OPENSSL

```bash
    OPENSSL_VERSION="3.6.3"
    OPENSSL_PREFIX = "你openssl想要安装的路径"

    curl -fL --retry 3 --retry-delay 5 \
            "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
            -o openssl.tar.gz
    tar -xzf openssl.tar.gz
    cd "openssl-${OPENSSL_VERSION}"
    # 关键三点：
    #   1. shared          —— 必须产出 libcrypto.so，FFI 才能 dlopen
    #   2. '-Wl,-rpath,$(LIBRPATH)' —— 单引号，让 make 展开；否则 openssl 会链到系统库
    #   3. --enable-new-dtags        —— 生成 RUNPATH，保证 LD_LIBRARY_PATH 能覆盖
    ./Configure \
        --prefix="$OPENSSL_PREFIX" \
        --openssldir="$OPENSSL_PREFIX/ssl" \
        --libdir=lib \
        shared \
        '-Wl,-rpath,$(LIBRPATH)' \
        -Wl,--enable-new-dtags

    make -j"$(nproc)"
    make install_sw install_ssldirs
```

### 安装OpenResty

```bash
    OPENSSL_PREFIX = "你openssl想要安装的路径"
    OPENRESTY_PREFIX = "你Openresty安装路径"
    OPENRESTY_VERSION = "1.25.2.3"

    curl -fL --retry 3 --retry-delay 5 \
        "https://openresty.org/download/openresty-${OPENRESTY_VERSION}.tar.gz" \
        -o openresty.tar.gz
    tar -xzf openresty.tar.gz
    cd "openresty-${OPENRESTY_VERSION}"

    # 改用 -I / -L 指向已安装的共享库，并把 rpath 编进 nginx
    ./configure \
        --prefix="$OPENRESTY_PREFIX" \
        --with-pcre-jit \
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-pcre-jit \
        --with-luajit \
        --with-stream \
        --with-stream_ssl_module \
        --with-cc-opt="-I$OPENSSL_PREFIX/include" \
        --with-ld-opt="-L$OPENSSL_PREFIX/lib -Wl,-rpath,$OPENSSL_PREFIX/lib -Wl,--enable-new-dtags"

    make -j"$(nproc)"
    make install
```

## SM2

### 引入
```lua
local sm2 = require("resty.gmsm.sm2")
```

### 初始化上下文
```lua
local ctx = sm2:new()
```

### 创建秘钥
```lua
local err = ctx:generate_key()
```

### 导出 Base64 格式秘钥
```lua
local pub_b64, err = ctx:export_public()
local priv_b64, err = ctx:export_private()
```

### 导入 Base64 格式秘钥
```lua
local err = ctx:import_public(pub_b64)
local err = ctx:import_private(priv_b64)
```

### 加解密
```lua
local cipher, err = ctx:encrypt(plaintext)
local plain, err = ctx:decrypt(cipher)
```

### 加签验签
```lua
local err = ctx:set_sm2_id(id) -- 不设置使用默认的 1234567812345678
local signtext, err = ctx:sign(data, id?)
local boolean, err = ctx:verify(data, signtext, id?)
```

## SM3

### 引入
```lua
local sm3 = require("resty.gmsm.sm3")
```

### 获取哈希
```lua
local hash, err = sm3.hash(data)
```

## SM4

### 引入
```lua
local sm4 = require("resty.gmsm.sm4")
```

### 生成秘钥/iv
```lua
local key, err = sm4.generate_key(16)
local iv, err = sm4.generate_iv(16) -- gcm iv长度一般为12
```

### ECB、CFB
```lua
local ctx = sm4:new(key, "cfb") -- 或者ecb
local cipher, err = ctx:encrypt(data)
local plain, err = ctx:decrypt(cipher)
```

### CBC、OFB
```lua
local ctx = sm4:new(key, "cbc", iv) -- 或者ofb
local cipher, err = ctx:encrypt(data)
local plain, err = ctx:decrypt(cipher)
```

### CTR

encrypt和decrypt方法兼容流式调用，不论使用CTR是否使用流式加解密在完成时都必须调用finish方法

```lua
local ctx_enc = sm4:new(key, "ctr")
local cipher1, err = ctx_enc:encrypt(data1)
local cipher2, err = ctx_enc:encrypt(data2)
local cipher3, err = ctx_enc:encrypt(data3)
ctx_enc:finish()

local ctx_dec = sm4:new(key, "ctr")
local plain, err = ctx_dec:decrypt(cipher1..cipher2..cipher3)
ctx_dec:finish()
```

### GCM
和CTR类似，在完成时需要调用finish，加密上下文调用finish会返回tag信息。 解密上下文调用finish时要传入tag进行完整性验证

```lua
local ctx_enc = sm4:new(key, "gcm", iv, aad)
local cipher1, err = ctx_enc:encrypt(data1)
local cipher2, err = ctx_enc:encrypt(data2)
local cipher3, err = ctx_enc:encrypt(data3)
local tag, err = ctx_enc:finish()

local ctx_dec = sm4:new(key, "gcm", iv, aad)
local plain, err = ctx_dec:decrypt(cipher1..cipher2..cipher3)
local err = ctx_dec:finish(tag) -- 报错则表示完整性验证失败
```

## 编码

### base64
```lua
local base64 = require("resty.gmsm.base64")
local encode = base64.encode(data)
local deocde, err = base64.decode(encode)
```

### hex
```lua
local hex = require("resty.gmsm.hex")
local encode = hex.encode(data)
local decode = hex.decode(encode)
```