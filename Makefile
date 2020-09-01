GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%S%z)

.PHONY: installer test all clean

kbs:
	cd cmd/kbs && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/kbs/version.GitHash=$(GITCOMMIT)" -o kbs

kbs-installer: kbs
	mkdir -p installer
	cp pkg/kbs/dist/linux/kbs.service installer/kbs.service
	cp pkg/kbs/dist/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/kbs/kbs installer/kbs
	makeself installer deployments/installer/kbs-$(VERSION).bin "KBS $(VERSION)" ./install.sh
	rm -rf installer

ihub:
	cd cmd/ihub && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/ihub/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/ihub/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/ihub/version.GitHash=$(GITCOMMIT)" -o ihub

ihub-installer: ihub
	mkdir -p installer
	cp pkg/ihub/dist/linux/ihub.service installer/ihub.service
	cp pkg/ihub/dist/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/ihub/ihub installer/ihub
	makeself installer deployments/installer/ihub-$(VERSION).bin "IHub $(VERSION)" ./install.sh
	rm -rf installer

hvs:
	cd cmd/hvs && GOOS=linux GOSUMDB=off GOPROXY=direct go build -ldflags "-X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.BuildDate=$(BUILDDATE) -X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.Version=$(VERSION) -X github.com/intel-secl/intel-secl/v3/pkg/hvs/version.GitHash=$(GITCOMMIT)" -o hvs

hvs-installer: hvs
	mkdir -p installer
	cp build/linux/EndorsementCA-external.pem installer/EndorsementCA-external.pem
	cp build/linux/hvs.service installer/hvs.service
	cp build/linux/install.sh installer/install.sh && chmod +x installer/install.sh
	cp cmd/hvs/hvs installer/hvs
	makeself installer deployments/installer/hvs-$(VERSION).bin "HVS $(VERSION)" ./install.sh
	rm -rf installer

installer: hvs-installer ihub-installer kbs-installer

ihub-docker: ihub
	docker build . -f build/image/Dockerfile-ihub -t isecl/ihub:$(VERSION)
	docker save isecl/ihub:$(VERSION) > deployments/docker/docker-ihub-$(VERSION)-$(GITCOMMIT).tar

hvs-docker: hvs
	docker build . -f build/image/Dockerfile-hvs -t isecl/hvs:$(VERSION)
	docker save isecl/hvs:$(VERSION) > deployments/docker/docker-hvs-$(VERSION)-$(GITCOMMIT).tar

hvs-swagger:
	mkdir -p docs/swagger
	swagger generate spec -c docs\/shared\/hvs -o ./docs/swagger/hvs-openapi.yml --scan-models
	swagger validate ./docs/swagger/hvs-openapi.yml

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

all: clean installer test

clean:
	rm -f cover.*
	rm -rf deployments/installer/*.bin
	rm -rf deployments/docker/*.tar
