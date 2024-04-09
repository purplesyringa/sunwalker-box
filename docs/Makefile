all: renderer/node_modules
	bun run ./renderer

clean:
	rm -r Rendered

renderer/node_modules: renderer/package.json
	cd renderer && bun install --frozen-lockfile --yarn
