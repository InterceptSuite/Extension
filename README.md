# InterceptSuite Extensions

Community and official extension examples for [InterceptSuite](https://interceptsuite.com/) - a network interception and analysis tool.

## What are Extensions?

Extensions let you decode, display, and re-encode protocol-specific traffic intercepted by InterceptSuite. Each extension is a Python file that plugs into the InterceptSuite GUI and adds a dedicated tab showing human-readable data for a protocol.

## Available Extensions

| Extension | Protocol | Port(s) | Description |
|-----------|----------|---------|-------------|
| [postgresql](postgresql/) | PostgreSQL | 5432 | Decodes and re-encodes PostgreSQL wire protocol v3 messages |
| [mqtt](mqtt/) | MQTT | 1883, 8883 | Decodes and re-encodes MQTT 3.1.1 control packets |


## Documentation

Full Extension API reference: https://interceptsuite.com/docs/interceptsuite/extension-api/

## Writing Your Own Extension

Each extension must contain a file with an `InterceptSuiteExtension` class:

```python
from InterceptSuite.Extensions.APIs.Logging import ExtensionLogger

class InterceptSuiteExtension:

    def register_interceptor_api(self, interceptor):
        interceptor.set_extension_name('My Extension')
        interceptor.set_extension_version('1.0.0')
        interceptor.AddDataViewerTab('My Tab', MyHandler())
        ExtensionLogger.Log('My Extension loaded')
```

The handler class passed to `AddDataViewerTab` must implement:

```python
class MyHandler:

    def should_show_tab(self, data) -> bool:
        # Return True if this extension applies to the intercepted packet
        ...

    def fetchdata(self, data) -> str:
        # Return decoded text to display in the tab
        ...

    def updatedata(self, data) -> str | None:
        # Return re-encoded raw bytes (as latin-1 string) when the user edits,
        # or None if nothing changed / edit is invalid
        ...
```

### `data` dictionary keys

| Key | Type | Description |
|-----|------|-------------|
| `raw_data` | `bytearray` | Raw intercepted bytes |
| `data` | `str` | Raw bytes as latin-1 string (fallback) |
| `edited_data` | `str` | Current editor content (only in `updatedata`) |
| `source_port` | `int` | Source port |
| `destination_port` | `int` | Destination port |
| `direction` | `str` | `"Client → Server"` or `"Server → Client"` |

## License

MIT
