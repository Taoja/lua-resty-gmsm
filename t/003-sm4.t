use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: SM4 ECB, CBC, CFB and OFB round trips
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm4 = require "resty.gmsm.sm4"
            local data = "hello world"
            local modes = {"ecb", "cbc", "cfb", "ofb"}
            local key = string.rep("k", 16)
            local iv = string.rep("i", 16)

            for _, mode in ipairs(modes) do
                local ctx = sm4:new(key, mode, iv)
                local cipher, encrypt_err = ctx:encrypt(data)
                local plain, decrypt_err = ctx:decrypt(cipher)
                if encrypt_err or decrypt_err or plain ~= data then
                    ngx.say("SM4 " .. mode .. " failed")
                    return
                end
            end

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 2: SM4 CTR streaming round trip
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local sm4 = require "resty.gmsm.sm4"
            local key = string.rep("k", 16)
            local data1, data2, data3 = "hell", "o w", "orld"
            local enc = sm4:new(key, "ctr")
            local c1 = enc:encrypt(data1)
            local c2 = enc:encrypt(data2)
            local c3 = enc:encrypt(data3)
            enc:finish()

            local dec = sm4:new(key, "ctr")
            local plain, decrypt_err = dec:decrypt(c1 .. c2 .. c3)
            local finish_err = dec:finish()
            if decrypt_err or finish_err or plain ~= data1 .. data2 .. data3 then
                ngx.say("SM4 CTR failed")
                return
            end

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]

=== TEST 3: SM4 GCM authenticated round trip
--- skip_eval
    my $ver = $ENV{OPENSSL_VERSION} // '';
    return 0 if $ver eq '';                       # 未设版本号就不跳过（本地跑照常执行）
    $ver =~ s/^\s*openssl[-\s]*//i;               # 兼容 "openssl-3.0.0" / "OpenSSL 3.5.0" 这类前缀
    my ($major, $minor);
    if ($ver =~ /(\d+)\.(\d+)/) {
        ($major, $minor) = ($1, $2);
    } elsif ($ver =~ /(\d+)/) {
        ($major, $minor) = ($1, 0);
    } else {
        return 0;                                 # 解析不出版本号，不跳过
    }
    # SM4-GCM 自 OpenSSL 3.0 起进入 default provider
    return 0 if $major > 3 || ($major == 3 && $minor >= 0);
    "SM4-GCM requires OpenSSL >= 3.0, got $ENV{OPENSSL_VERSION}"
--- http_config
    lua_package_path "$prefix/lib/?.lua;$prefix/../../lib/?.lua;;";
--- config
    location /t {
        content_by_lua_block {
            local version = os.getenv("OPENSSL_VERSION")
            
            local sm4 = require "resty.gmsm.sm4"
            local key = string.rep("k", 16)
            local iv = string.rep("i", 12)
            local aad = "additional authenticated data"
            local data = "hello world, this is a test message"
            local enc = sm4:new(key, "gcm", iv, aad)
            local cipher, encrypt_err = enc:encrypt(data)
            local tag, tag_err = enc:finish()

            local dec = sm4:new(key, "gcm", iv, aad)
            local plain, decrypt_err = dec:decrypt(cipher)
            local verify_err = dec:finish(tag)
            if encrypt_err or tag_err or decrypt_err or verify_err or plain ~= data then
                ngx.say("SM4 GCM failed")
                return
            end

            ngx.say("ok")
        }
    }
--- request
GET /t
--- response_body
ok
--- no_error_log
[error]
