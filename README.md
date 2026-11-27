# agent-sandbox-bench

Does a hardened container profile reduce the share of a 22-action attack suite that causes real harm (%), and what share of 10 benign agent tasks does it break (%)? Baseline: the same image, tool calls and lab services under default Docker settings.

> Work in progress. Step-by-step instructions from a fresh clone to `make measure` will be added here.

## Requirements

- Docker (nothing else is installed on the host)

## Quick start

```sh
git clone https://github.com/tiennt220805/agent-sandbox-bench.git
cd agent-sandbox-bench
make measure
```
