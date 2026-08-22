PROJECT_NAME=go_port_scanner
COMMAND=./cmd/go-port-scanner
.PHONY: build clean

build:
	go build -o $(PROJECT_NAME) $(COMMAND)

build_static:
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $(PROJECT_NAME)_static $(COMMAND)

clean:
	rm -f $(PROJECT_NAME)

run: build
	./$(PROJECT_NAME)
