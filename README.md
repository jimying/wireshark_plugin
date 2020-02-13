# wireshark_plugin
My plugin for wireshark

## RFC4571 plugin
Fix current dissecting problem on RTP over TCP(RFC4571)

Before use:
![before1](res/rfc4571/before_use.png)

![before2](res/rfc4571/before_use_statistics.png)

After:
![example](res/rfc4571/after_use.png)

![example](res/rfc4571/after_statistics.png)

### usage
1. Copy the content of the lua plugin.
2. Choose Tool->Lua->Evaluate, paste the content and evaluate.
3. Choose Decode As `RFC4571`
![use lua](res/lua_evaluate.png)

