PROJECT_NAME=go_port_scanner
.PHONY: build clean

build:
	go build -o $(PROJECT_NAME) ./main.go

build_static:
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $(PROJECT_NAME)_static ./main.go

clean:
	rm -f $(PROJECT_NAME)

run: build
	./$(PROJECT_NAME)