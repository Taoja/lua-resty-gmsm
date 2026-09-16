local ffi = require "ffi"
local err = require("resty.gmsm.err_print")

ffi.cdef [[
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct ossl_lib_ctx_st OSSL_LIB_CTX;
typedef struct ossl_param_st OSSL_PARAM;
struct ossl_param_st {
    const char *key;
    unsigned int data_type;
    void *data;
    size_t data_size;
    size_t return_size;
};

EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

const EVP_CIPHER *EVP_sm4_ecb(void);
const EVP_CIPHER *EVP_sm4_cbc(void);
const EVP_CIPHER *EVP_sm4_cfb128(void);
const EVP_CIPHER *EVP_sm4_ofb(void);
const EVP_CIPHER *EVP_sm4_ctr(void);

OSSL_PARAM OSSL_PARAM_construct_size_t(const char *key, size_t *buf);
OSSL_PARAM OSSL_PARAM_construct_octet_string(const char *key, void *buf,
    size_t bsize);
int EVP_CIPHER_CTX_get_params(EVP_CIPHER_CTX *ctx, OSSL_PARAM params[]);
int EVP_CIPHER_CTX_set_params(EVP_CIPHER_CTX *ctx, const OSSL_PARAM params[]);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       void *engine, const unsigned char *key,
                       const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       void *engine, const unsigned char *key,
                       const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                     int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *ctx, const char *algorithm,
    const char *properties);
int RAND_bytes(unsigned char *buf, int num);
const char *OpenSSL_version(int);
]]

local openssl = ffi.C

local _M = {
  Version = '1.0.1',
  Openssl_Version = ffi.string(openssl.OpenSSL_version(0))
}
_M.__index = _M

-- SM4 模式枚举
local MODE = {
  ECB = "ecb",
  CBC = "cbc",
  CFB = "cfb",
  OFB = "ofb",
  CTR = "ctr",
  GCM = "gcm",
}

_M.MODE = MODE

-- 获取 SM4 密码对象
local function get_sm4_cipher(mode)
  if mode == MODE.ECB then
    return openssl.EVP_sm4_ecb()
  elseif mode == MODE.CBC then
    return openssl.EVP_sm4_cbc()
  elseif mode == MODE.CFB then
    return openssl.EVP_sm4_cfb128()
  elseif mode == MODE.OFB then
    return openssl.EVP_sm4_ofb()
  elseif mode == MODE.CTR then
    return openssl.EVP_sm4_ctr()
  elseif mode == MODE.GCM then
    return openssl.EVP_CIPHER_fetch(nil, "SM4-GCM", nil)
  else
    error("Unsupported mode: " .. tostring(mode))
  end
end

--- 生成随机秘钥
--- @param length number? 秘钥长度，默认16
--- @return string? 私钥字符串
--- @return string? 错误信息
function _M.generate_key(length)
  if not length then length = 16 end
  if length ~= 16 and length ~= 24 and length ~= 32 then
    return nil, "SM4 key length must be 16, 24 or 32 bytes"
  end
  local key = ffi.new("unsigned char[?]", length)
  if openssl.RAND_bytes(key, length) <= 0 then
    return nil, "Failed to generate random key:" .. err()
  end
  return ffi.string(key, length), nil
end

--- 生成随机iv
--- @param length number? iv长度，默认16
--- @return string? iv字符串
--- @return string? 错误信息
function _M.generate_iv(length)
  if not length then length = 16 end
  local iv = ffi.new("unsigned char[?]", length)
  if openssl.RAND_bytes(iv, length) <= 0 then
    return nil, "Failed to generate random IV"
  end
  return ffi.string(iv, length), nil
end

--- 构造函数
--- @param key string 私钥
--- @param mode string? 模式枚举
--- @param iv string? iv
--- @param aad string? aad
function _M:new(key, mode, iv, aad)
  mode = mode or MODE.CBC
  iv = iv or ""
  local obj = {
    key = key,
    mode = mode,
    iv = iv,
    ctx_enc = nil,
    ctx_dec = nil,
  }

  if mode == MODE.GCM then
    obj.aad = ffi.cast("unsigned char*", aad)
    obj.aad_size = #aad
  end

  return setmetatable(obj, self)
end

function _M:encrypt_init()
  local ctx = openssl.EVP_CIPHER_CTX_new()
  local cipher = get_sm4_cipher(self.mode)
  local key_data = ffi.cast("const unsigned char*", self.key)
  local iv_data = nil
  if #self.iv > 0 then
    iv_data = ffi.cast("const unsigned char*", self.iv)
  end

  if openssl.EVP_EncryptInit_ex(ctx, cipher, nil, key_data, iv_data) <= 0 then
    openssl.EVP_CIPHER_CTX_free(ctx)
    return "Failed to initialize encryption context:" .. err()
  end

  if self.mode == MODE.GCM then
    local outl = ffi.new("int[1]")
    if openssl.EVP_EncryptUpdate(ctx, nil, outl, self.aad, self.aad_size) <= 0 then
      openssl.EVP_CIPHER_CTX_free(ctx)
      return nil, "Failed to encrypt aad data:" .. err()
    end
  end

  self.ctx_enc = ctx
  return nil
end

function _M:encrypt_finalize()
  local outl = ffi.new("int[1]")
  local out_buf = ffi.new("unsigned char[?]", 16)
  if openssl.EVP_EncryptFinal_ex(self.ctx_enc, out_buf, outl) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
    return nil, "Failed to finalize encryption:" .. err()
  end
  
  local cipher = ffi.string(out_buf, outl[0])
  local tag = nil

  if self.mode == MODE.GCM then
    local params = ffi.new("OSSL_PARAM[2]") 
    local c_key = ffi.cast("unsigned char*", "tag")
    local outtag = ffi.new("unsigned char[16]")
    params[0] = openssl.OSSL_PARAM_construct_octet_string(c_key, outtag, 16)
    if openssl.EVP_CIPHER_CTX_get_params(self.ctx_enc, params) <= 0 then
      openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
      return nil, "Failed to get params:"..err()
    end
    tag = ffi.string(outtag, 16)
  end
  
  openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
  self.ctx_enc = nil
  return cipher, nil, tag
end

-- 内部加密函数
function _M:encrypt_internal(plaintext)
  local outl = ffi.new("int[1]")
  local in_data = ffi.cast("const unsigned char*", plaintext)
  local in_len = #plaintext
  local out_buf = ffi.new("unsigned char[?]", in_len + 16)

  -- 加密
  if openssl.EVP_EncryptUpdate(self.ctx_enc, out_buf, outl, in_data, in_len) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_enc)
    return nil, "Failed to encrypt data:" .. err()
  end
  local cipher = ffi.string(out_buf, outl[0])
  return cipher, nil
end

function _M:decrypt_init()
  local ctx = openssl.EVP_CIPHER_CTX_new()
  local cipher = get_sm4_cipher(self.mode)
  local key_data = ffi.cast("const unsigned char*", self.key)
  local iv_data = nil
  if #self.iv > 0 then
    iv_data = ffi.cast("const unsigned char*", self.iv)
  end
  
  if openssl.EVP_DecryptInit_ex(ctx, cipher, nil, key_data, iv_data) <= 0 then
    openssl.EVP_CIPHER_CTX_free(ctx)
    return "Failed to initialize decryption context:" .. err()
  end

  if self.mode == MODE.GCM then
    local outl = ffi.new("int[1]")
    if openssl.EVP_DecryptUpdate(ctx, nil, outl, self.aad, self.aad_size) <= 0 then
      openssl.EVP_CIPHER_CTX_free(ctx)
      return nil, "Failed to decrypt aad data:" .. err()
    end
  end

  self.ctx_dec = ctx
  return nil
end

function _M:decrypt_finalize(tag)
  local outl = ffi.new("int[1]")
  local out_buf = ffi.new("unsigned char[?]", 16)

  if self.mode == MODE.GCM then
    local params = ffi.new("OSSL_PARAM[2]") 
    local c_key = ffi.cast("unsigned char*", "tag")
    local intag = ffi.cast("unsigned char*", tag)
    params[0] = openssl.OSSL_PARAM_construct_octet_string(c_key, intag, #tag)
    if openssl.EVP_CIPHER_CTX_set_params(self.ctx_dec, params) <= 0 then
      openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
      return nil, "Failed to set params:"..err()
    end
  end
  
  if openssl.EVP_DecryptFinal_ex(self.ctx_dec, out_buf, outl) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
    return nil, "Failed to finalize encryption:" .. err()
  end
  
  local plain = ffi.string(out_buf, outl[0])
  openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
  return plain, nil
end

-- 内部解密函数
function _M:decrypt_internal(ciphertext)
  local outl = ffi.new("int[1]")
  local in_data = ffi.cast("const unsigned char*", ciphertext)
  local in_len = #ciphertext
  local out_buf = ffi.new("unsigned char[?]", in_len)
  
  -- 解密
  if openssl.EVP_DecryptUpdate(self.ctx_dec, out_buf, outl, in_data, in_len) <= 0 then
    openssl.EVP_CIPHER_CTX_free(self.ctx_dec)
    return nil, "Failed to decrypt data:" .. err()
  end

  local plain = ffi.string(out_buf, outl[0])
  return plain, nil
end

--- sm4加密
--- @param plaintext string 需要加密的明文字符串
--- @return string? 加密后的密文信息
--- @return string? 错误信息
function _M:encrypt(plaintext)
  -- 初始化加密上下文
  if not self.ctx_enc then
    local errorMsg = self:encrypt_init()
    if errorMsg then
      return nil, errorMsg
    end
  end
  
  -- 加密
  local ciphertext, errorMsg = self:encrypt_internal(plaintext)
  if errorMsg then
    return nil, errorMsg
  end
  
  -- 结束
  if self.mode ~= MODE.CTR and self.mode ~= MODE.GCM then
    local finaltext, errorMsg = self:encrypt_finalize()
    if errorMsg then
      return nil, errorMsg
    end
    ciphertext = ciphertext .. finaltext
  end

  return ciphertext, nil
end

--- sm4解密
--- @param ciphertext string 需要解密的密文字符串
--- @return string? 解密后的明文信息
--- @return string? 错误信息
function _M:decrypt(ciphertext)
  -- 初始化解密上下文
  if not self.ctx_dec then
    local errorMsg = self:decrypt_init()
    if errorMsg then
      return nil, errorMsg
    end
  end
  
  -- 解密
  local plaintext, errorMsg = self:decrypt_internal(ciphertext)
  if errorMsg then
    return nil, errorMsg
  end

  -- 结束
  if self.mode ~= MODE.CTR and self.mode ~= MODE.GCM then
    local finaltext, errorMsg = self:decrypt_finalize()
    if errorMsg then
      return nil, errorMsg
    end
    plaintext = plaintext .. finaltext
  end

  return plaintext, nil
end

function _M:finish(inTag)
  if self.ctx_enc then
    local finaltext, errorMsg, tag = self:encrypt_finalize()
    if errorMsg then
      return nil, errorMsg
    end
    return tag, nil
  end
  if self.ctx_dec then
    local finaltext, errorMsg = self:decrypt_finalize(inTag)
    if errorMsg then
      return errorMsg
    end
    return nil
  end
end

return _M