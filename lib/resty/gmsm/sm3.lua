-- sm3.lua
local ffi = require("ffi")
local err = require("resty.gmsm.err_print")
local load_lib = require("resty.gmsm.load_lib")

ffi.cdef [[
    typedef struct evp_md_st EVP_MD;

    const EVP_MD *EVP_sm3(void);
    int EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size,
                   const EVP_MD *type, void *impl);
    const char *OpenSSL_version(int);
]]

local openssl = load_lib()

local _M = {
  Version = '1.0.1',
  Openssl_Version = ffi.string(openssl.OpenSSL_version(0))
}

_M.DIGEST_LENGTH = 32

function _M.hash(data)
  if type(data) ~= "string" then
    return nil, "the input must be string"
  end

  local out_buf = ffi.new("unsigned char[?]", _M.DIGEST_LENGTH)
  local out_len = ffi.new("unsigned int[1]")

  if openssl.EVP_Digest(data, #data, out_buf, out_len, openssl.EVP_sm3(), nil) ~= 1 then
    return nil, "Failed do digest:" .. err()
  end

  return ffi.string(out_buf, out_len[0]), nil
end

return _M
