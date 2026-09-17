local ffi = require("ffi")

local candidates = {
  Windows = {
    "libcrypto-3-x64",
    "libcrypto-3",
    "libcrypto",
    "crypto",
    "libcrypto-3-x86"
  },
  Linux = {
    "libcrypto.so.3",
    "libcrypto.so",
    "libcrypto",
    "crypto"
  },
  Darwin = {
    "libcrypto.3.dylib",
    "libcrypto.dylib",
    "libcrypto",
    "crypto"
  },
  BSD = {
    "libcrypto.so.3",
    "libcrypto.so",
    "libcrypto",
    "crypto"
  }
}

local function detect_os()
  if jit and jit.os then
    return jit.os
  end

  local platform = package.config and package.config:sub(1, 1)
  if platform == "\\" then
    return "Windows"
  end

  local uname = io.popen("uname -s 2>/dev/null")
  if uname then
    local out = uname:read("*l")
    uname:close()
    if out then
      if out == "Darwin" then return "Darwin" end
      if out == "Linux" then return "Linux" end
      if out:match("BSD") then return "BSD" end
    end
  end

  return "Linux"
end

local function load_lib()
  local os_name = detect_os()
  local names = candidates[os_name] or candidates.Linux

  for _, name in ipairs(names) do
    local ok, lib = pcall(ffi.load, name)
    if ok and lib then
      return lib
    end
  end

  error("failed to load openssl on " .. os_name .. ", tried: " .. table.concat(names, ", "), 2)
end

return load_lib
