local ffi = require "ffi"
local load_lib = require "resty.gmsm.load_lib"

ffi.cdef [[
void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u), void *u);
]]

local openssl = load_lib()

local function print()
  local error_str
  local function error_callback(str, len, u)
    error_str = ffi.string(str, len)
    return 1
  end
  local cb = ffi.cast("int (*)(const char *, size_t, void *)", error_callback)
  openssl.ERR_print_errors_cb(cb, nil)
  if error_str then
    return error_str
  else
    return ""
  end
end

return print