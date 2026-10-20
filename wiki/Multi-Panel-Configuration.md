# Multi-Panel Configuration

MAP routes calls by `panel_id`. Configure `MAP_PANELS_JSON` with one object per panel or use `MAP_PANELS_JSON_B64` for systemd. Every panel needs a unique ID and HTTPS base URL; add only the key types required for the tasks you intend to perform. Do not commit credentials.

Read the [configuration reference](https://github.com/RealmsNetwork/MAP/blob/main/docs/configuration.md).
