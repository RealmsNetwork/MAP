# MCP tool reference

Tool schemas are exposed by the server. The chosen panel's API version and key determine which operations succeed.

## Discovery and generic API requests

### `list_panels()`

Lists panel IDs, names, base URLs, and which API namespaces have configured keys, without returning key values.

### `panel_status(panel_id, api="auto")`

Checks the selected provider. `auto` uses the Client API for Pterodactyl/Pelican and a native status path for other providers; MCSManager defaults to `/api/overview`, while AMP uses its POST `Core/GetStatus` method. A 401/403 usually indicates authentication/permission problems; a 404 may mean the configured status endpoint is unavailable.

### `panel_api_request(panel_id, api, method, path, query_params=None, json_body=None, raw_body=None, content_type=None, timeout_seconds=30)`

General-purpose endpoint tool. For Pterodactyl/Pelican, `api` is a supported namespace and `path` is relative to it. For MCSManager, Crafty, PufferPanel, Calagopus, AMP, or generic REST, use `api="native"`; `path` is relative to the configured `api_base_path`. Query parameters are passed separately. Supported methods: GET, POST, PUT, PATCH, DELETE. Supply at most one of JSON body and raw text body.

This tool can make destructive changes when the key permits them. Review the method, endpoint, target object, and body before write requests.


## CubeCoders AMP

AMP's API differs from REST panels that use bearer keys. Set `provider` to `amp` and configure `auth_username`/`auth_password` (plus `amp_totp_token` when needed). MAP submits the login request, caches the returned `SESSIONID`, and injects it into native JSON POST requests. Use `panel_api_request` with `api="native"`, `method="POST"`, and the documented method path, such as `Core/GetStatus`. The request body must be a JSON object. `panel_status` uses AMP's `Core/GetStatus` POST path.

Create a least-privilege AMP account. MAP does not expose the password/session token through `list_panels` and redacts session IDs from responses. The actual permissions granted by the AMP account still determine what it can do.

## MCSManager-native tools

These tools use MCSManager's native API rather than sending Pterodactyl routes to it.

| Tool | Parameters | Purpose |
| --- | --- | --- |
| `mcsmanager_list_instances` | `panel_id, daemon_id, page=1, page_size=50` | List instances for a daemon. Page size is capped at 50. |
| `mcsmanager_instance_action` | `panel_id, daemon_id, instance_uuid, action` | Start, stop, restart, or kill an instance. |
| `mcsmanager_instance_command` | `panel_id, daemon_id, instance_uuid, command` | Send a command through the native HTTP API. |
| `mcsmanager_instance_output_log` | `panel_id, daemon_id, instance_uuid, size="10KB"` | Read the instance output log. |

Calagopus uses its own API rather than Pterodactyl-compatible endpoints. Use the instance's `/api` documentation and `panel_api_request` with `api="native"`; configure `api_base_path` as `/api` and use a Calagopus API key.

For other MCSManager endpoints, use `panel_api_request` with `api="native"` and the endpoint documented for the installed version. MCSManager 9.x and 10.x differ; verify endpoint semantics before making writes.

## Pterodactyl/Pelican-compatible server tools

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
