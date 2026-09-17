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
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
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

EVP_PKEY_CTX *EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX *libctx,
    const char *name,
    const char *propquery);
int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);

EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
const EVP_MD *EVP_sm3(void);
int EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                       const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);
int EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
                         const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
int EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, const void *id, size_t id_len);
const char *OpenSSL_version(int);
]]

local NID_sm2 = ffi.cast("int", 1172)
local EVP_PKEY_SM2 = NID_sm2
local openssl = load_lib()

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

  self.key[0] = key
  if self.key[0] == ffi.NULL then
    return "import private key error:" .. err()
  end
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
  self.key[0] = key
  if self.key[0] == ffi.NULL then
    return "import publick key error:" .. err()
  end
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
  local genctx = openssl.EVP_PKEY_CTX_new_from_name(nil, "SM2", nil)
  if genctx == nil then
    return "generate key fail:" .. err()
  end

  if openssl.EVP_PKEY_paramgen_init(genctx) <= 0 then
    return "generate key fail:" .. err()
  end

  if openssl.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(genctx, NID_sm2) <= 0 then
    return "generate key fail:" .. err()
  end

  if openssl.EVP_PKEY_keygen_init(genctx) <= 0 then
    return "generate key fail:" .. err()
  end

  if openssl.EVP_PKEY_keygen(genctx, self.key) <= 0 then
    return "generate key fail:" .. err()
  end
  openssl.EVP_PKEY_CTX_free(genctx)
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
  local id_len = #use_id

  local ctx = openssl.EVP_MD_CTX_new()
  if ctx == nil then
    return nil, "EVP_MD_CTX_new failed"
  end

  local pctx = ffi.new("EVP_PKEY_CTX*[1]")

  if openssl.EVP_DigestSignInit(ctx, pctx, openssl.EVP_sm3(), nil, self.key[0]) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "EVP_DigestSignInit failed"
  end

  if openssl.EVP_PKEY_CTX_set1_id(pctx[0], use_id, id_len) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "EVP_PKEY_CTX_set1_id failed"
  end

  if openssl.EVP_DigestSignUpdate(ctx, data, #data) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return nil, "EVP_DigestSignUpdate failed"
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
  local id_len = #use_id

  local ctx = openssl.EVP_MD_CTX_new()
  if ctx == nil then
    return false, "EVP_MD_CTX_new failed"
  end

  local pctx = ffi.new("EVP_PKEY_CTX*[1]")

  if openssl.EVP_DigestVerifyInit(ctx, pctx, openssl.EVP_sm3(), nil, self.key[0]) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return false, "EVP_DigestVerifyInit failed"
  end

  if openssl.EVP_PKEY_CTX_set1_id(pctx[0], use_id, id_len) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return false, "EVP_PKEY_CTX_set1_id failed"
  end

  if openssl.EVP_DigestVerifyUpdate(ctx, data, #data) <= 0 then
    openssl.EVP_MD_CTX_free(ctx)
    return false, "EVP_DigestVerifyUpdate failed"
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
