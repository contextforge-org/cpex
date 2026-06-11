## Before you begin

Update the environment variables in .env

All values except PLUGINS_GITHUB_TOKEN have defaults.

```dotenv
### Plugin installation
# Comma Separated Values used by install with --type monorepo
# The default value is https://github.com/ibm/cpex-plugins
# PLUGINS_REPO_URLS="https://github.com/ibm/cpex-plugins"

# registry path (default shown below)
# PLUGIN_REGISTRY_FOLDER=data

# Github API (default shown below)
# PLUGINS_GITHUB_API=api.github.com

# PLUGINS_GITHUB_TOKEN=<github token>
### end Plugin installation
```

## Plugin installation using the cli

```bash
  python cpex/tools/cli.py plugin --help                              
                                                                                                                                                                                                                                                                                                      
 Usage: cli.py plugin [OPTIONS] [CMD_ACTION] [SOURCE]                                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                                                                                      
 List, search, install or uninstall plugins.                                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                                                                                      
default install type is monorepo                                                                                                                                
 Examples:                                                                                                                                                       
 python cpex/tools/cli.py plugin info pii                                                                                                                        
 python cpex/tools/cli.py plugin search pii                                                                                                                      
 python cpex/tools/cli.py plugin --type monorepo search pii                                                                                                      
 python cpex/tools/cli.py plugin --type monorepo install cpex-pii-filter                                                                                         
 python cpex/tools/cli.py plugin --type pypi install "ExamplePlugin@>=0.1.0"                                                                                     
 python cpex/tools/cli.py plugin --type test-pypi install "cpex-test-plugin@>=0.1.1"                                                                             
 python cpex/tools/cli.py plugin --type git install "cpex-test-plugin @ git+https://github.com/tedhabeck/cpex-test-plugin@main"                                  
 python cpex/tools/cli.py plugin versions cpex-test-plugin                                                                                                       
 python cpex/tools/cli.py plugin uninstall cpex-pii-filter.                                                                                                      

╭─ Arguments ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│   cmd_action      [CMD_ACTION]  One of: list|info|install|search|uninstall                                                                                                                                                                                                                         │
│   source          [SOURCE]      The pypi, git, or local folder where the plugin resides                                                                                                                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --type  -t      TEXT  The types of plugins to list.  One of: monorepo|pypi|test-pypi|git|local  Defaults to monorepo if unspecified.                                                                                                                                                               │
│ --help                Show this message and exit.                                                                                                                                                                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

```


## Installation catalog and plugin registry

### Catalog update sequence diagram

Catalog update from monorepo IBM/cpex-plugins:

```mermaid
sequenceDiagram
     participant cli
     participant dotenv
     participant catalog
     participant pygithub
     cli->>catalog: update
     dotenv->>catalog: PLUGINS_REPO_URLS
     dotenv->>catalog: PLUGINS_GITHUB_TOKEN
     catalog->>pygithub: find pyproject.toml files
     catalog->>catalog: for each pyproject.toml
     catalog->>catalog: extract [project].name
     catalog->>pygithub: find plugin-manifest.yaml
     pygithub->>catalog: plugin-manifest.yaml
     catalog-->catalog: update plugin-manifest.yaml with monorepo details
     catalog->>catalog: save plugin manifest to plugin-catalog
     catalog->>cli: catalog update completed
```

### Plugin installation sequence diagrams
Installation from git monorepo:

`python cpex/tools/cli.py plugin --type monorepo install pii`

```mermaid
sequenceDiagram
     participant User
     participant cli
     participant installed_plugin_registry
     participant catalog
     participant subprocess
     participant python
     participant pip
     participant git
     participant monorepo
     User->>cli: python cpex/tools/cli.py plugin --type monorepo install pii
     cli->>catalog: update
     catalog->>monorepo: get available plugins
     monorepo->>catalog: available plugins
     catalog->>catalog: add monorepo.package_source to downloaded plugin-manifest.yaml
     catalog->>cli: available plugins
     cli->>User: select plugin from available plugins
     User->>cli: selected plugin
     cli->>catalog: install selected plugin
     catalog->>subprocess: python -m pip install git+<manifest.monorepo.package_source>
     subprocess->>python: -m pip install git+<manifest.monorepo.package_source>
     python->>pip: install git+<manifest.monorepo.package_source>
     pip->>git: download <package_source> to site-packages
     git->>monorepo: download <package_source> to site-packages
     monorepo->>git: package installed
     git->>pip: package installed
     pip->>python: package installed
     python->>subprocess: rc=0
     subprocess->>catalog: plugin installed
     catalog->>cli: PluginManifest
     cli->>installed_plugin_registry: register plugin PluginManifest
     installed_plugin_registry->>cli: plugin registered
     cli->>cli: update PLUGINS_CONFIG_FILE (i.e. plugins/config.yaml)
     cli->>User: plugin installed OK
```

 Installation from pypi:

`python cpex/tools/cli.py --type pypi install <package_name>>=<package_Version>`

```mermaid
sequenceDiagram
     participant User
     participant cli
     participant catalog
     participant installed_plugin_registry
     participant subprocess
     participant python
     participant pip
     participant pypi (Python Package Index)
     User->>cli: python cpex/tools/cli.py plugin --type pypi install <package_name><version_constaint>
     cli->>catalog: install_from_pypi(<package_name><version_constraint>
     catalog->>subprocess: python -m pip download <package_name><version_constraint> to temp
     subprocess->>python: -m pip download <package_name><version_constraint> to temp
     python->>pip: download <package_name><version_constraint>
     pip->>pypi (Python Package Index): download <package_name> to temp
     pypi (Python Package Index)->>python: downloaded OK
     python->>subprocess: rc=0
     subprocess->>catalog: extracted_folder
     catalog->>catalog: Loads and parse the plugin-manifest.yaml
     catalog->>catalog: if manifest.kind is isolated_venv initialize isolated venv and STOP here.
     catalog->>cli: PluginManifest (isolated_venv)
     catalog->>subprocess: python -m pip install <package_name><version_constraint>
     subprocess->>python: -m pip install <package_name><version_constraint>
     python->>pip: install <package_name><version_constraint>
     pip->>pypi (Python Package Index): download <package_name> to site-packages
     pypi (Python Package Index)->>python: downloaded OK
     python->>subprocess: rc=0
     subprocess->>catalog: plugin installed
     catalog->>catalog: load plugin manifest
     catalog->>catalog: package_info.pypi_package=<package_name>
     catalog->>catalog: package_info.version_constraint=<version_constraint>
     catalog->>catalog: save updated manifest to plugin-catalog
     catalog->>cli: PluginManifest
     cli->>installed_plugin_registry: register plugin
     installed_plugin_registry->>cli: plugin registered
     cli->>cli: update PLUGINS_CONFIG_FILE (i.e. plugins/config.yaml)
     cli->>User: plugin installed OK
```
Note: installation from test.pypi.org is also supported using --type test-pypi. e.g:

`python cpex/tools/cli.py plugin --type test-pypi install "cpex-plugin-test@>=0.1.1" `

### Uninstall

Example uninstall of plugin:
`python cpex/tools/cli.py plugin uninstall cpex-pii-filter`


### Pligin information query sequence diagram

Query information for installed plugins:

`python cpex/tools/cli.py plugin info`

```mermaid
sequenceDiagram
     participant User
     participant cli
     participant installed_plugin_registry
     User->>cli: python cpex/tools/cli.py plugin info
     cli->>installed_plugin_registry: pii
     installed_plugin_registry->>cli: InstalledPluginInfo[]
     cli->>User: InstalledPluginInfo[]
```

Example output:
```zsh
   python cpex/tools/cli.py plugin info
{
  "name": "cpex-test-plugin",
  "kind": "isolated_venv",
  "version": "0.2.0",
  "installation_type": "monorepo",
  "installation_path": "/Users/habeck/tedhabeck/contextforge-plugins-framework/plugins/cpex_test_plugin/.venv/lib/python3.13/site-packages/cpex_test_plugin",
  "installed_at": "2026-05-01T00:14:26.123924+00:00Z",
  "installed_by": "habeck",
  "package_source": "https://github.com/tedhabeck/cpex-test-plugin",
  "editable": false
}
```