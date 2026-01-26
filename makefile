test:
	go test -v ./...

run: 
	go run .

tidy:
	go get -u ./... && go mod tidy


lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

