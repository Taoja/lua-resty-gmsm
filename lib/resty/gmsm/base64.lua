local ffi = require("ffi")
local err = require("resty.gmsm.err_print")
local load_lib = require("resty.gmsm.load_lib")

ffi.cdef [[
  int EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int n);
  int EVP_DecodeBlock(unsigned char *t, const unsigned char *f, int n);
]]

local openssl = load_lib()

local base64 = {}

local function trim_trailing_zeros(buf, len)
    if len == 0 then return 0 end
    local pos = buf + len        -- 指向末尾之后
    local base = buf
    while pos > base and pos[-1] == 0 do
        pos = pos - 1
    end
    return tonumber(pos - base)
end

function base64.encode(data)
  local len = #data
  local out_len = math.ceil(len / 3) * 4 + 1
  local out_buf = ffi.new("unsigned char[?]", out_len)

  local ret = openssl.EVP_EncodeBlock(out_buf, data, len)
  return ffi.string(out_buf, ret)
end

function base64.decode(b64)
  local input = ffi.cast("const unsigned char*", b64)
  local out_len = math.floor(#b64 * 3 / 4)
  local out_buf = ffi.new("unsigned char[?]", out_len)
  local ret = openssl.EVP_DecodeBlock(out_buf, input, #b64)
  if ret < 0 then
    return nil, "Failed base64 decode:" .. err()
  end
  local real_len = trim_trailing_zeros(out_buf, ret)
  return ffi.string(out_buf, real_len), nil
end

return base64
