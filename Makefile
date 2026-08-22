PROJECT_NAME=go_port_scanner
COMMAND=./cmd/go-port-scanner
REMOTE?=origin

.PHONY: build build_static clean release run

build:
	go build -o $(PROJECT_NAME) $(COMMAND)

build_static:
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $(PROJECT_NAME)_static $(COMMAND)

clean:
	rm -f $(PROJECT_NAME)

run: build
	./$(PROJECT_NAME)

release:
	@set -eu; \
	test -f VERSION || { echo "VERSION file not found" >&2; exit 1; }; \
	release_version="$$(tr -d '[:space:]' < VERSION)"; \
	release_version="$${release_version#v}"; \
	printf '%s\n' "$$release_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z]+)*$$' || { \
		echo "Invalid VERSION: $$release_version" >&2; \
		exit 1; \
	}; \
	release_tag="v$$release_version"; \
	release_branch="$$(git branch --show-current)"; \
	test -n "$$release_branch" || { echo "Cannot release from detached HEAD" >&2; exit 1; }; \
	release_remote="$(REMOTE)"; \
	git remote get-url "$$release_remote" >/dev/null; \
	go test -race ./...; \
	git add --all; \
	if git diff --cached --quiet; then \
		echo "Nothing to commit. Update VERSION before creating a release." >&2; \
		exit 1; \
	fi; \
	git commit -m "release: $$release_tag"; \
	git tag --force --annotate "$$release_tag" --message "Release $$release_tag"; \
	git push --force "$$release_remote" "HEAD:refs/heads/$$release_branch"; \
	git push --force "$$release_remote" "refs/tags/$$release_tag:refs/tags/$$release_tag"
