use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: which openssl does Lua see
--- main_config
env OPENSSL_VERSION;
--- config
location = /t { content_by_lua_block {
  local sm4 = require "resty.gmsm.sm4"
  local text = sm4.Openssl_Version
  local seen = text:match("^OpenSSL%s+(%S+)") or "?"
  local want = os.getenv("OPENSSL_VERSION")
  ngx.say("SEEN: ", text)
  ngx.say("WANT: ", tostring(want))
  if not want or want == "" then
    ngx.say("RESULT: SKIP")
  elseif want == seen then
    ngx.say("RESULT: PASS")
  else
    ngx.say("RESULT: FAIL")
  end
}}
--- request
GET /t
--- response_body_like
RESULT: (PASS|SKIP)