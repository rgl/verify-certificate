EXT = .exe

all: verify-certificate.zip

clean:
	rm -f verify-certificate*

verify-certificate${EXT}: *.go
	go build -o $@ -ldflags "-s"

verify-certificate.zip: verify-certificate${EXT}
	zip $@ $^

.PHONY: all clean
