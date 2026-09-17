local ffi = require "ffi"
local err = require("resty.gmsm.err_print")
local base64 = require("resty.gmsm.base64")
local load_lib = require("resty.gmsm.load_lib")

ffi.cdef [[
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct engine_st ENGINE;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct ec_key_st EC_KEY;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct evp_md_st EVP_MD;
typedef struct evp_cipher_st EVP_CIPHER;

void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **a, const unsigned char **pp,
    long length);
EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
int i2d_PrivateKey(const EVP_PKEY *a, unsigned char **pp);
EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **in, long len);
int i2d_PUBKEY(const EVP_PKEY *a, unsigned char **out);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx,
    unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);

EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
    int cmd, int p1, void *p2);
int EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type);

/* 以下两个在 3.x 是导出函数，在 1.1.1 只是宏（没有对应符号），
 * 声明本身不会解析符号，实际调用前会做符号探测。 */
EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
    const char *name,
    const char *propquery);
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, int len);
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
const EVP_MD *EVP_sm3(void);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                       const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                         const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
const char *OpenSSL_version(int);
void ERR_clear_error(void);
]]

local NID_sm2 = ffi.cast("int", 1172)
local EVP_PKEY_SM2 = NID_sm2
local EVP_PKEY_EC = 408                        -- NID_X9_62_id_ecPublicKey
local EVP_PKEY_ALG_CTRL = 0x1000
-- 1.1.1 里这几个 ctrl 命令是宏：EVP_PKEY_ALG_CTRL + n（3.x 的 SET1_ID 另有取值，
-- 但 3.x 提供了函数版本，所以下面的常量只会在 1.1.1 的 ctrl 分支里用到）
local EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID = EVP_PKEY_ALG_CTRL + 1
local EVP_PKEY_CTRL_SET1_ID = EVP_PKEY_ALG_CTRL + 11
local EVP_PKEY_OP_PARAMGEN = 2                 -- 1 << 1
local EVP_PKEY_OP_KEYGEN = 4                   -- 1 << 2

local openssl = load_lib()

--- 探测符号是否存在：1.1.1 上访问 3.x 专有符号会直接抛 "undefined symbol"
--- @param name string 符号名
--- @return function? 可用则返回可调用对象，否则 nil
local function try_symbol(name)
  local ok, sym = pcall(function()
    return openssl[name]
  end)
  if ok and sym ~= nil then
    return sym
  end
  return nil
end

local fn_new_from_name = try_symbol("EVP_PKEY_CTX_new_from_name")
local fn_set_ec_curve = try_symbol("EVP_PKEY_CTX_set_ec_paramgen_curve_nid")
local fn_set1_id = try_symbol("EVP_PKEY_CTX_set1_id")
local fn_set_alias_type = try_symbol("EVP_PKEY_set_alias_type")
local fn_clear_error = try_symbol("ERR_clear_error")

local function clear_error()
  if fn_clear_error ~= nil then
    fn_clear_error()
  end
end

--- 设置 SM2/EC 密钥生成使用的曲线
--- 3.x 有导出函数；1.1.1 只有宏，按 EVP_PKEY_CTX_ctrl 手动展开
--- @param ctx EVP_PKEY_CTX*
--- @param nid number 曲线 NID
--- @return number 与 OpenSSL 一致的返回码（>0 成功）
local function ctx_set_ec_curve(ctx, nid)
  if fn_set_ec_curve ~= nil then
    return fn_set_ec_curve(ctx, nid)
  end

  return openssl.EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
    EVP_PKEY_OP_PARAMGEN + EVP_PKEY_OP_KEYGEN,
    EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, nil)
end

--- 设置 SM2 签名/验签用的 user id（Z 值计算用）
--- 3.x 有导出函数；1.1.1 只有宏 EVP_PKEY_CTX_ctrl(ctx, -1, -1, ...)
--- @param ctx EVP_PKEY_CTX*
--- @param id string sm2 id
--- @return number 与 OpenSSL 一致的返回码（>0 成功）
local function ctx_set1_id(ctx, id)
  if fn_set1_id ~= nil then
    return fn_set1_id(ctx, id, #id)
  end

  -- 用显式 buffer 承载 id，避免直接把 Lua 字符串转成 void* 的生命周期风险
  local id_buf = ffi.new("unsigned char[?]", #id + 1)
  ffi.copy(id_buf, id, #id)

  return openssl.EVP_PKEY_CTX_ctrl(ctx, -1, -1,
    EVP_PKEY_CTRL_SET1_ID, #id, ffi.cast("void *", id_buf))
end

--- 带 sm2 id 的 DigestSign/Verify 初始化
---
--- 关键差异：1.1.1 的 do_sigver_init() 在 init 阶段就调用 pmeth->digest_custom
--- （pkey_sm2_digest_custom），而它要求 sm2 id 已经设置，否则直接报
--- SM2_R_ID_NOT_SET 并返回 0 —— 但此时 pctx 已经建好并回写给调用者。
--- 所以 1.1.1 上的正确顺序是：先 init（必然失败）→ 在 pctx 上设置 id → 再 init 一次。
--- 3.x 的 digest_custom 在 final 阶段才调用，第一次 init 就成功，不会走重试分支。
---
--- @param init_fn function EVP_DigestSignInit 或 EVP_DigestVerifyInit
--- @param ctx EVP_MD_CTX*
--- @param pctx EVP_PKEY_CTX*[1]
--- @param pkey EVP_PKEY*
--- @param id string sm2 id
--- @return boolean 是否初始化成功
local function digest_init_with_id(init_fn, ctx, pctx, pkey, id)
  local ok = init_fn(ctx, pctx, openssl.EVP_sm3(), nil, pkey) > 0

  if pctx[0] == ffi.NULL then
    return false
  end

  if ctx_set1_id(pctx[0], id) <= 0 then
    return false
  end

  if not ok then
    clear_error()
    ok = init_fn(ctx, pctx, openssl.EVP_sm3(), nil, pkey) > 0
  end

  return ok
end

--- 把 EC 类型的 key 别名成 SM2 类型
--- 1.1.1 下 d2i/EC keygen 得到的都是 EVP_PKEY_EC，EC 的 pmeth 既没有
--- encrypt/decrypt 也不支持 SET1_ID，必须换成 SM2 的 pmeth 才能用；
--- 3.x 下 d2i 解出来的已经是 SM2，set_alias_type 会直接返回 1。
--- @param key EVP_PKEY*
--- @return boolean 是否可用
local function alias_to_sm2(key)
  if key == ffi.NULL or fn_set_alias_type == nil then
    -- 3.x 新版本已移除 set_alias_type，此时 d2i/gen 出来的本就是 SM2，无需转换
    return true
  end

  return fn_set_alias_type(key, EVP_PKEY_SM2) > 0
end

local _M = {
  Version = '1.0.1',
  Openssl_Version = ffi.string(openssl.OpenSSL_version(0))
}
_M.__index = _M

local DEFAULT_SM2_ID = "1234567812345678"

local function trim_string(s)
  if type(s) ~= "string" then
    return s
  end
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function normalize_binary_input(data)
  if type(data) ~= "string" then
    return nil, "input must be a string"
  end

  local str = trim_string(data)
  if str == "" then
    return nil, "empty input"
  end

  if str:find("-----BEGIN") ~= nil then
    return nil, "unsupported input format; use base64 text instead"
  end

  if str:find("%z") ~= nil then
    return str, nil
  end

  local compact = str:gsub("%s+", "")
  if compact:match("^[A-Za-z0-9%+%/%=]+$") and #compact % 4 == 0 and compact:len() > 0 then
    local decoded, base64_err = base64.decode(compact)
    if decoded ~= nil and #decoded > 0 and base64_err == nil then
      return decoded, nil
    end
  end

  return str, nil
end

--- 初始化实例
function _M:new()
  local obj = setmetatable({}, self)
  obj.key = ffi.new("EVP_PKEY*[1]")
  obj.key[0] = ffi.NULL
  obj.sm2_id = DEFAULT_SM2_ID
  return obj
end

function _M:import_private(data)
  local normalized, normalize_err = normalize_binary_input(data)
  if normalize_err then
    return normalize_err
  end

  local input = ffi.cast("const unsigned char*", normalized)
  local input_ptr = ffi.new("const unsigned char*[1]", input)

  local key = openssl.d2i_AutoPrivateKey(nil, input_ptr, #normalized)
  if key == ffi.NULL then
    local fallback_ptr = ffi.new("const unsigned char*[1]", input)
    key = openssl.d2i_PrivateKey(EVP_PKEY_SM2, nil, fallback_ptr, #normalized)
  end

  if key == ffi.NULL then
    return "import private key error:" .. err()
  end

  -- d2i 出来的是 EVP_PKEY_EC（id-ecPublicKey + sm2p256v1），
  -- 1.1.1 下必须转成 SM2 才能加解密 / 设置 sm2 id
  if not alias_to_sm2(key) then
    return "import private key error: not an SM2 key"
  end

  self.key[0] = key
  return nil
end

function _M:import_public(data)
  local normalized, normalize_err = normalize_binary_input(data)
  if normalize_err then
    return normalize_err
  end

  local input = ffi.cast("const unsigned char*", normalized)
  local input_ptr = ffi.new("const unsigned char*[1]", input)
  local key = openssl.d2i_PUBKEY(nil, input_ptr, #normalized)
  if key == ffi.NULL then
    return "import publick key error:" .. err()
  end

  if not alias_to_sm2(key) then
    return "import public key error: not an SM2 key"
  end

  self.key[0] = key
  return nil
end

--- 设置签名验签sm2id
--- @param id string sm2_id
--- @return string? 错误信息
function _M:set_sm2_id(id)
  if type(id) ~= "string" then
    return "ID must be a string"
  end
  self.sm2_id = id
  return nil
end

--- 生成sm2公私钥对
--- @return string? 错误信息
function _M:generate_key()
  -- OpenSSL 3.x：SM2 keymgmt 支持 paramgen + keygen，走原路径
  if fn_new_from_name ~= nil then
    local genctx = fn_new_from_name(nil, "SM2", nil)
    if genctx ~= nil then
      local ok = openssl.EVP_PKEY_paramgen_init(genctx) > 0
        and ctx_set_ec_curve(genctx, NID_sm2) > 0
        and openssl.EVP_PKEY_keygen_init(genctx) > 0
        and openssl.EVP_PKEY_keygen(genctx, self.key) > 0

      openssl.EVP_PKEY_CTX_free(genctx)
      if ok then
        return nil
      end
    end
  end

  -- OpenSSL 1.1.1（以及上面的兜底）：sm2_pkey_meth 里 keygen/paramgen 都是 NULL，
  -- EVP_PKEY_keygen_init 会直接返回 -2（unsupported），
  -- 所以按 sm2p256v1 曲线用 EC 的 keygen 生成，再 alias 成 SM2
  local genctx = openssl.EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nil)
  if genctx == nil then
    return "generate key fail:" .. err()
  end

  local ok = openssl.EVP_PKEY_keygen_init(genctx) > 0
    and ctx_set_ec_curve(genctx, NID_sm2) > 0
    and openssl.EVP_PKEY_keygen(genctx, self.key) > 0

  openssl.EVP_PKEY_CTX_free(genctx)

  if not ok or self.key[0] == ffi.NULL then
    return "generate key fail:" .. err()
  end

  if not alias_to_sm2(self.key[0]) then
    return "generate key fail: cannot convert EC key to SM2"
  end

  return nil
end

--- 导出der格式公钥
--- @return string? der格式公钥字符串
--- @return string? 错误信息
function _M:export_public_to_der()
  if self.key[0] == ffi.NULL then
    return nil, "no key loaded"
  end
  local len = openssl.i2d_PUBKEY(self.key[0], nil)
  local buf = ffi.new("unsigned char[?]", len)
  local buf_ptr = ffi.new("unsigned char*[1]", buf)
  openssl.i2d_PUBKEY(self.key[0], buf_ptr)
  return ffi.string(buf, len), nil
end

function _M:export_public(format)
  local der, der_err = self:export_public_to_der()
  if der_err ~= nil then
    return nil, der_err
  end
  local fmt = format or "base64"
  if fmt == "base64" then
    return base64.encode(der), nil
  else
    return nil, "unsupported public key format: use base64"
  end
end

--- 导出der格式私钥
--- @return string? der格式私钥字符串
--- @return string? 错误信息
function _M:export_private_to_der()
  if self.key[0] == ffi.NULL then
    return nil, "no key loaded"
  end

  local len = openssl.i2d_PrivateKey(self.key[0], nil)
  local buf = ffi.new("unsigned char[?]", len)
  local buf_ptr = ffi.new("unsigned char*[1]", buf)
  openssl.i2d_PrivateKey(self.key[0], buf_ptr)
  return ffi.string(buf, len), nil
end

function _M:export_private(format)
  local der, der_err = self:export_private_to_der()
  if der_err ~= nil then
    return nil, der_err
  end
  local fmt = format or "base64"
  if fmt == "base64" then
    return base64.encode(der), nil
  else
    return nil, "unsupported private key format: use base64"
  end
end

--- sm2加密
--- @param str string 需要加密的明文信息
--- @return string? 加密后密文信息
--- @return string? 错误信息
function _M:encrypt(str)
  if self.key[0] == ffi.NULL then
    return nil, "no key loaded"
  end
  local ctx = openssl.EVP_PKEY_CTX_new(self.key[0], nil)
  if ctx == nil then
    return nil, "EVP_PKEY_CTX_new fail:" .. err()
  end
  local out_len = ffi.new("size_t[1]")
  local input = ffi.cast("const unsigned char*", str)
  if openssl.EVP_PKEY_encrypt_init(ctx) <= 0 then
    openssl.EVP_PKEY_CTX_free(ctx)
    return nil, "encrypt init fail:" .. err()
  end
  if openssl.EVP_PKEY_encrypt(ctx, nil, out_len, input, #str) <= 0 then
    openssl.EVP_PKEY_CTX_free(ctx)
    return nil, "get encrypt len fail:" .. err()
  end
  local out = ffi.new("unsigned char[?]", out_len[0])
  if openssl.EVP_PKEY_encrypt(ctx, out, out_len, input, #str) <= 0 then
    openssl.EVP_PKEY_CTX_free(ctx)
    return nil, "encrypt fail:" .. err()
  end
  openssl.EVP_PKEY_CTX_free(ctx)

  return ffi.string(out, out_len[0]), nil
end

--- sm2解密
--- @param str string 需要解密的密文信息
--- @return string? 解密后明文信息
--- @return string? 错误信息
function _M:decrypt(str)
  if self.key[0] == ffi.NULL then
    return nil, "no key loaded"
  end

  local normalized, normalize_err = normalize_binary_input(str)
  if normalize_err then
    return nil, normalize_err
  end

  local ctx = openssl.EVP_PKEY_CTX_new(self.key[0], nil)
  if ctx == nil then
    return nil, "EVP_PKEY_CTX_new fail:" .. err()
  end

  local out_len = ffi.new("size_t[1]")
  local input = ffi.cast("const unsigned char*", normalized)
  if openssl.EVP_PKEY_decrypt_init(ctx) <= 0 then
    openssl.EVP_PKEY_CTX_free(ctx)
    return nil, "decrypt init fail:" .. err()
  end
  if openssl.EVP_PKEY_decrypt(ctx, nil, out_len, input, #normalized) <= 0 then
    openssl.EVP_PKEY_CTX_free(ctx)
    return nil, "get decrypt len fail:" .. err()
  end
  local out = ffi.new("unsigned char[?]", out_len[0])
  if openssl.EVP_PKEY_decrypt(ctx, out, out_len, input, #normalized) <= 0 then
    openssl.EVP_PKEY_CTX_free(ctx)
    return nil, "decrypt fail:" .. err()
  end
  openssl.EVP_PKEY_CTX_free(ctx)
  return ffi.string(out, out_len[0]), nil
end

--- sm2加签
--- @param data string 待签名的明文信息
--- @param id string? 自定义sm2_id
--- @return string? 签名
--- @return string? 错误信息
function _M:sign(data, id)
  if self.key[0] == ffi.NULL then
    return nil, "no key loaded"
  end

  local use_id = id or self.sm2_id

  local ctx = openssl.EVP_MD_CTX_new()
  if ctx == nil then
    return nil, "EVP_MD_CTX_new failed"
  end

  local pctx = ffi.new("EVP_PKEY_CTX*[1]")

  if not digest_init_with_id(openssl.EVP_DigestSignInit, ctx, pctx,
                             self.key[0], use_id) then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "EVP_DigestSignInit failed"
  end

  -- 注意：1.1.1 里 EVP_DigestSignUpdate 只是宏，展开后就是 EVP_DigestUpdate，
  -- 直接查 EVP_DigestSignUpdate 会 undefined symbol，所以统一用 EVP_DigestUpdate
  if openssl.EVP_DigestUpdate(ctx, data, #data) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "EVP_DigestUpdate failed"
  end

  local siglen = ffi.new("size_t[1]")
  if openssl.EVP_DigestSignFinal(ctx, nil, siglen) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "get signature length failed"
  end

  local sig = ffi.new("unsigned char[?]", siglen[0])
  if openssl.EVP_DigestSignFinal(ctx, sig, siglen) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "EVP_DigestSignFinal failed"
  end

  openssl.EVP_MD_CTX_free(ctx)
  return ffi.string(sig, siglen[0]), nil
end

--- sm2验签
--- @param data string 待验签的明文信息
--- @param signature string 签名
--- @param id string? 自定义sm2_id
--- @return boolean? 是否匹配
--- @return string? 错误信息
function _M:verify(data, signature, id)
  if self.key[0] == ffi.NULL then
    return nil, "no key loaded"
  end

  local use_id = id or self.sm2_id

  local ctx = openssl.EVP_MD_CTX_new()
  if ctx == nil then
    return false, "EVP_MD_CTX_new failed"
  end

  local pctx = ffi.new("EVP_PKEY_CTX*[1]")

  if not digest_init_with_id(openssl.EVP_DigestVerifyInit, ctx, pctx,
                             self.key[0], use_id) then
    openssl.EVP_MD_CTX_free(ctx)
    return false, "EVP_DigestVerifyInit failed"
  end

  if openssl.EVP_DigestUpdate(ctx, data, #data) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return false, "EVP_DigestUpdate failed"
  end

  local sig = ffi.cast("const unsigned char*", signature)
  local result = openssl.EVP_DigestVerifyFinal(ctx, sig, #signature)

  openssl.EVP_MD_CTX_free(ctx)

  if result == 1 then
    return true, nil
  elseif result == 0 then
    return false, nil
  else
    return nil, "EVP_DigestVerifyFinal error"
  end
end

return _M
