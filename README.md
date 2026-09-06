# xray-config-generator

An interactive terminal application and command-line tool for building Xray VLESS/REALITY cascade configurations and deploying them through 3x-ui panels. A cascade connects several servers in a defined order (for example, `entry -> middle -> exit`). The same topology can be rendered as standalone JSON or applied to configured panels.

## What it does

- Builds one or more routes and creates the identifiers and cryptographic values required by each route, including UUIDs, X25519 REALITY keys, short IDs, SNI values, XHTTP paths, and listening ports.
- Uses XHTTP with REALITY by default, with TCP/RAW available as an alternative transport.
- Checks SNI candidates locally and can ask compatible remote panels to check targets from their own servers.
- Connects to 3x-ui using bearer-token authentication, legacy username/password sessions, or automatic selection between the supported methods.
- Detects the panel API layout, reads existing settings, and merges only the objects owned by the selected cascade ID.
- Saves backups before deployment and attempts to restore the previous state if an update fails.

Unrelated panel inbounds, outbounds, routing rules, and other settings are intended to remain untouched. Panels that expose runtime validation can verify the assembled Xray configuration; older APIs receive the checks that their endpoints support.

## Requirements and installation

The project is packaged as a Python application. On Debian or Ubuntu, install Python's virtual-environment support if it is not present, then install the package from the repository:

```bash
sudo apt install python3-venv
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
config-generator
```

The interactive interface is useful for building a topology and testing panel connections. Save a topology file when you want to repeat generation, deployment, or removal from the command line.

## Interactive workflow

1. Add a server with a name, address, and complete panel URL. Include any secret path configured by the panel.
2. Choose token, legacy, or automatic authentication for each panel.
3. Test panel access before making changes.
4. Define the route order, port pool, SNI candidates, and transport.
5. Review the generated topology and deploy it to the selected panels.

Current 3x-ui versions should use an API token. Older installations can use a panel username and password. Automatic mode tries a configured token first and falls back to the legacy session when credentials are available. TLS verification should remain enabled for panels with trusted certificates. It can be disabled for a panel using a self-signed certificate when that is required for the connection.

## Command-line examples

Print a sample topology and test connectivity to panels:

```bash
config-generator example
config-generator panel-test topology.json
```

Check remote SNI candidates, generate files, deploy a topology, or remove the objects associated with its cascade ID:

```bash
config-generator panel-sni topology.json -o remote-sni.json
config-generator generate topology.json --check-sni -o cascade-output
config-generator deploy topology.json -o cascade-output
config-generator remove topology.json
```

Generation can be used without connecting to a panel. Deployment authenticates to each server, reads its current configuration, chooses available ports, backs up the settings, and writes the receiving inbounds plus the matching routing objects. Repeating a deployment with the same cascade ID replaces that cascade rather than duplicating it. Removal is likewise scoped to the ID in the topology.

## Credentials and generated files

Topology files saved by the interface may contain panel URLs, usernames, passwords, or API tokens. Keep them private; the interface attempts to restrict their file permissions. Deployment backups also contain server configuration and should be treated as sensitive.

Generated client and server JSON can contain REALITY private keys. Protect the output directory and do not commit it to a public repository. Redacted topology output omits panel tokens and passwords, but should still be reviewed before sharing.
