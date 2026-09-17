local ffi = require("ffi")
local load_lib = require("resty.gmsm.load_lib")

ffi.cdef [[
  char *OPENSSL_buf2hexstr(const unsigned char *str, long buflen);
  unsigned char *OPENSSL_hexstr2buf(const char *str, long *buflen);
]]

local openssl = load_lib()
local _M = {}

function _M.encode(data)
  local input = ffi.cast("const unsigned char*", data)
  local c_str = openssl.OPENSSL_buf2hexstr(input, #data)
  return ffi.string(c_str)
end

function _M.decode(data)
  local out_len = ffi.new("long[1]")
  local input = ffi.cast("const char*", data)
  local out_buf = openssl.OPENSSL_hexstr2buf(input, out_len)
  return ffi.string(out_buf, out_len[0])
end

return _M
