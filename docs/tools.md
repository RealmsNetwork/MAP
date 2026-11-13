# MCP tool reference

Tool schemas are exposed by the server. The chosen panel's API version and key determine which operations succeed.

## Discovery and generic API requests

### panel_api_schema(panel_id)

Returns the provider API reference. For Calagopus, MAP attempts to retrieve the live OpenAPI 3 JSON from the panel root at /openapi.json. If the host disables that endpoint, it reports the HTTP result and provides the Scalar documentation page at /api. For Pterodactyl/Pelican, it selects the official versioned v1 or v2 API reference and reports which configured API namespaces have credentials.

### panel_context(panel_id, page=1, per_page=50)

Builds a context snapshot from live panel responses. Calagopus returns visible servers, their effective per-server permission identifiers, limits, feature limits, node and primary allocation. Pterodactyl/Pelican returns visible servers and, when a Client key is configured, each server's meta.user_permissions, ownership, limits and allocations. A * permission means full access within that server. This tool never elevates permissions; a missing credential or denied endpoint remains unavailable.


### `list_panels()`

Lists panel IDs, names, base URLs, and which API namespaces have configured keys, without returning key values.

### `panel_status(panel_id, api="auto")`

Checks the selected provider. `auto` uses the Client API for Pterodactyl/Pelican and a native status path for other providers; MCSManager defaults to `/api/overview`, while AMP uses its POST `Core/GetStatus` method. A 401/403 usually indicates authentication/permission problems; a 404 may mean the configured status endpoint is unavailable.

### `panel_api_request(panel_id, api, method, path, query_params=None, json_body=None, raw_body=None, content_type=None, timeout_seconds=30)`

General-purpose endpoint tool. For Pterodactyl, api is client, application, or (on 2.x) admin; Pelican supports client and application. For Calagopus, MCSManager, Crafty, PufferPanel, AMP, or generic REST, use api=native; path is relative to the configured api_base_path. Query parameters are passed separately. Supported methods: GET, POST, PUT, PATCH, DELETE. Supply at most one of JSON body and raw text body. This is the catch-all for every other endpoint the configured key permits, including network/firewall, databases, schedules, subusers, backup groups, startup, mounts/devices, activity, account, nodes/infrastructure, and admin endpoints.

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

Calagopus uses its own API rather than Pterodactyl-compatible endpoints. Use panel_api_schema to fetch the live OpenAPI 3 document when exposed and the instance's /api Scalar reference. Use panel_api_request with api=native and configure api_base_path as /api (or leave it empty if the configured base URL already includes /api). GET /api/client/permissions returns the permission catalog; panel_context returns effective per-server permission identifiers. Calagopus has its own Client and Admin API routers, so paths under client/... and admin/... are available subject to the key's permissions.

For other MCSManager endpoints, use `panel_api_request` with `api="native"` and the endpoint documented for the installed version. MCSManager 9.x uses `remote_uuid` as the daemon selector; 10.x uses `daemonId`. MAP switches the parameter based on `panel_version`. State-changing instance actions use POST for both generations; 10.x also permits GET for some routes in its frontend, but MAP avoids GET for mutations.

## Server tools for Pterodactyl/Pelican and Calagopus

The common server tools also support Calagopus. Pterodactyl file deletion is permanent and there is no trash-view/restore tool in that adapter; Calagopus retains its native trash behavior. MAP routes those calls through its native API at `/api/client/servers/{server}/...`; it does not send Pterodactyl namespace requests to Calagopus. `list_panels` reports `dedicated_server_tools: true` when these operations are available.

| Operation | Pterodactyl/Pelican behavior | Calagopus behavior |
| --- | --- | --- |
| Server listing | Client or Application API; auto prefers a configured Client key, then Application. | GET /api/client/servers with page/per-page pagination. |
| Resources, power, console | Client API routes; power uses the Pterodactyl signal field. | Native server routes; power uses the Calagopus action field. |
| File listing | Client API directory listing. | Directory listing with page and per_page. |
| Text read/write | Client API file contents and write routes. | Reads UTF-8 content even when labeled application/octet-stream; writes use text/plain. Binary files use the base64 transfer tools. |
| Directory, rename, delete | Create-folder, rename and delete routes; deletion is permanent (no trash viewer). | Uses files/create-directory, files/rename, and files/delete. Deletion goes to Calagopus trash by default; set permanent=true to permanently delete. |
| Backups | Client API create/list/delete; restore, download, lock, and other operations remain available through the generic API. | Native backup create/list/delete routes and ignored_files field. |
| Network and databases | Client API allocations and database routes; broader application operations where configured. | Native allocations, firewall, connections, databases, and managed DB Agent endpoints. |
| Schedules and access | Client API schedules and subuser routes. | Native schedules and subuser routes. |
| Binary upload/download | Signed Wings URLs, validated against the panel hostname or exact trusted Wings hosts. | Signed Wings URLs, validated against the panel hostname or exact trusted Wings hosts. |

Other Calagopus endpoints (activity, startup, schedules, databases, allocations, backup restore/groups, search, archives, and more) remain available through panel_api_request with api=native and paths from the installed panel's API reference. The Scalar documentation page is /api; upstream Calagopus serves OpenAPI JSON at the panel root /openapi.json, but a deployed host may return 404 if that route is disabled. panel_api_schema reports the actual result instead of pretending the schema was retrieved.

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

MAP obtains a signed URL for file transfers from the panel, then contacts Wings directly. That hostname must be the panel hostname or an exact entry in `MAP_TRUSTED_WINGS_HOSTS`. Redirects are disabled, signed URLs are not returned, and bodies are bounded. Calagopus returns `{url}` directly; Pterodactyl/Pelican return `attributes.url`.
