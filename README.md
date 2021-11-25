# rdpproxy

A reverse proxy for RDP protocol by using routing token

## Configuration

Command:

```shell
XKB_CONFIG_ROOT=./vendor/xkb ./rdpproxy config.json
```

`config.json` example:

```json
{
    "port": 3389,
    "api": "http://127.0.0.1:8080/api"
}
```

Example API payload:

```json
{"token":"example_token"}
```

Example server response:

```json
{
    "status": "ok",
    "ip": "192.0.2.0",
    "port": 3389,
    "username": "unused, optional"
}
```
