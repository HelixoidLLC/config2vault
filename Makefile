test:
	go test -v ./...

integration:
	go test -v --tags=integration ./...

build:
	GOOS=darwin GOARCH=386 go build -o=bin/config2vault-darwin-386
	GOOS=linux GOARCH=386 go build -o=bin/config2vault-linux-386
	GOOS=darwin GOARCH=amd64 go build -o=bin/config2vault-darwin-amd64
	GOOS=linux GOARCH=amd64 go build -o=bin/config2vault-linux-amd64

bump:
	gobump patch -w