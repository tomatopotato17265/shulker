.PHONY: build clean

build:
	go build -o bin/shulker .
	ln -sf shulker bin/minecraft

clean:
	rm -rf bin
