.PHONY: measure measure-ablation report verify replay clean

measure:
	@echo "TODO: run baseline, hardened, allowlist (>=5 runs)"

measure-ablation:
	@echo "TODO: run ablation configs and hardened-ro-hooks"

report:
	@echo "TODO: generate tables and charts from results/"

verify:
	@echo "TODO: check every number in REPORT.md against results/"

replay:
	@echo "TODO: recompute LLM-mode numbers from recordings"

clean:
	@echo "TODO: remove containers, networks and temporary workspaces"
