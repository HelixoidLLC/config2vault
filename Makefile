test:
	go test -v ./...

integration:
	go test -v --tags=integration ./...

build:
	rm -rf bin
	mkdir -p bin/mac
	GOOS=darwin GOARCH=386 go build -o=bin/mac/config2vault
	chmod +x bin/mac/config2vault
	mkdir -p bin/linux
	GOOS=linux GOARCH=386 go build -o=bin/linux/config2vault
	chmod +x bin/linux/config2vault

bump:
	gobump patch -w