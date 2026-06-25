---
title: "CLI Tools"
weight: 130
aliases:
  - /docs/cli/
---

# CLI Tools

CPEX includes the `cpex` command-line tool for scaffolding new plugin projects from templates.

---

## Installation

The CLI is included when you install CPEX:

```bash
pip install cpex
```

The `cpex` command becomes available in your environment. To use the `bootstrap` subcommand, install the CLI extras:

```bash
pip install "cpex[cli]"
```

---

## `cpex bootstrap`

Scaffolds a new plugin project from a cookiecutter template.

```bash
cpex bootstrap --destination ./my_plugin --template_type native
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--destination` | `-d` | `.` | Output directory for the new plugin project |
| `--template_type` | `-t` | `native` | Template type: `native`, `external`, or `isolated` |
| `--template_url` | `-u` | — | Custom template URL (overrides built-in templates) |
| `--vcs_ref` | `-r` | `main` | Git branch/tag/commit for remote templates |
| `--no_input` | — | `false` | Use defaults without prompting |
| `--dry_run` | — | `false` | Preview what would be created without writing files |

### Template Types

**`native`** — an in-process plugin with hook stubs for tools and prompts:

```bash
cpex bootstrap -d ./my_policy_plugin -t native
```

Creates:

```
my_policy_plugin/
├── __init__.py
└── plugin.py          # Plugin subclass with tool + prompt hook stubs
```

**`external`** — a standalone MCP server plugin with test scaffolding:

```bash
cpex bootstrap -d ./my_remote_plugin -t external
```

Creates:

```
my_remote_plugin/
├── my_remote_plugin/
│   ├── __init__.py
│   └── plugin.py      # Plugin subclass
└── tests/
    ├── __init__.py
    └── test_my_remote_plugin.py
```

**`isolated`** — a venv-isolated plugin:

```bash
cpex bootstrap -d ./my_sandboxed_plugin -t isolated
```

Creates:

```
my_sandboxed_plugin/
├── __init__.py
└── plugin.py          # Plugin subclass for venv isolation
```

### Dry Run

Preview what would be created without writing anything:

```bash
cpex bootstrap -d ./my_plugin -t native --dry_run
```

### Custom Templates

Point to your own cookiecutter template repository:

```bash
cpex bootstrap -d ./my_plugin -u https://github.com/my-org/plugin-template.git -r v2.0
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PLUGINS_CLI_COMPLETION` | `false` | Enable shell auto-completion |
| `PLUGINS_CLI_MARKUP_MODE` | `rich` | Help text rendering: `rich`, `markdown`, or `disabled` |
