# MCP tool reference

Tool schemas are exposed by the server. The chosen panel's API version and key determine which operations succeed.

## Discovery and generic API requests

### `list_panels()`

Lists panel IDs, names, base URLs, and which API namespaces have configured keys, without returning key values.

### `panel_status(panel_id, api="application")`

Makes a request against the selected namespace. A 401/403 usually indicates key/permission problems; a 404 may mean an endpoint is absent for the panel version.

### `panel_api_request(panel_id, api, method, path, query_params=None, json_body=None, raw_body=None, content_type=None, timeout_seconds=30)`

General-purpose endpoint tool. Choose endpoints documented for your panel version. `path` is relative to the selected namespace; query parameters are separate. Supported methods: GET, POST, PUT, PATCH, DELETE. Supply at most one of JSON body and raw text body.

This tool can make destructive changes when the key permits them. Review the method, endpoint, target object, and body before write requests.

## Dedicated server tools

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `list_servers` | `panel_id, page=1, api="application"` | Lists servers. |
| `server_resources` | `panel_id, server_id` | Reads state and resource usage. |
| `server_power` | `panel_id, server_id, signal` | Starts, stops, restarts, or kills; kill force-stops. |
| `server_console_command` | `panel_id, server_id, command` | Sends a server console command. |
| `server_list_files` | `panel_id, server_id, directory="/"` | Lists a directory. |
| `server_read_file` | `panel_id, server_id, file` | Reads text. |
| `server_write_file` | `panel_id, server_id, file, content` | Writes text (maximum 2 MB). |
| `server_create_directory` | `panel_id, server_id, name, root="/"` | Creates a directory. |
| `server_delete_files` | `panel_id, server_id, files, root="/"` | Permanently deletes paths. |
| `server_rename_files` | `panel_id, server_id, root, files` | Renames or moves paths. |
| `server_upload_file_base64` | `panel_id, server_id, filename, content_base64, directory="/"` | Uploads a bounded binary payload; filename is a basename. |
| `server_download_file_base64` | `panel_id, server_id, file` | Returns a bounded download as base64. |
| `server_create_backup` | `panel_id, server_id, name=None, ignored=None` | Starts a backup. |
| `server_list_backups` | `panel_id, server_id` | Lists backups. |
| `server_delete_backup` | `panel_id, server_id, backup_id` | Deletes a backup. |

MAP obtains a signed URL for file transfers from the panel, then contacts Wings directly. That hostname must be the panel hostname or an exact entry in `MAP_TRUSTED_WINGS_HOSTS`. Redirects are disabled, signed URLs are not returned, and bodies are bounded.
