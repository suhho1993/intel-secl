GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: installer test all clean

hvs:
	cd cmd/hvs && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.GitHash=$(GITCOMMIT)" -o hvs

hvs-installer: hvs
	mkdir -p bin/installer
	cp pkg/hvs/dist/linux/hvs.service bin/installer/hvs.service
	cp pkg/hvs/dist/linux/install.sh bin/installer/install.sh && chmod +x bin/installer/install.sh
	cp cmd/hvs/hvs bin/installer/hvs
	makeself bin/installer bin/hvs-$(VERSION).bin "HVS $(VERSION)" ./install.sh
	rm -rf bin/installer

installer: hvs-installer

swagger:
	mkdir -p out/swagger
	swagger generate spec -o ./out/swagger/openapi.yml --scan-models

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean installer test

clean:
	rm -f cover.*
	rm -rf bin/
