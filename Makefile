include /usr/share/dpkg/architecture.mk

# Go parameters
GO = go
GOBUILD = $(GO) build
GOCLEAN = $(GO) clean
DEB_BUILD = dpkg-buildpackage --build=full
NAME = fruitnanny

# Installation parameters
DESTDIR :=
prefix := /usr/local

ifeq ($(DEB_BUILD_GNU_TYPE),$(DEB_HOST_GNU_TYPE))
	GOBUILD=$(GO) build
# Debian cross compilation
else
	ifeq ($(DEB_HOST_ARCH),armhf)
		GOARCH=arm
	else
		$(error Unsupported crossbuild host type "$(DEB_HOST_ARCH)")
	endif

	ifeq ($(DEB_HOST_ARCH_OS),linux)
		GOOS=linux
	else
		$(error Unsupported crossbuild os type "$(DEB_HOST_ARCH_OS)")
	endif

	GOBUILD=GOARCH=$(GOARCH) GOOS=$(GOOS) $(GO) build -ldflags="-w -s"
endif


all: build

info:
	@echo "GO:     $(GO)"
	@echo "GOOS:   $(GOOS)"
	@echo "GOARCH: $(GOARCH)"

build:
	$(GOBUILD) -o $(NAME) -v main.go

# test:
#	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(NAME)
	rm -rf debian/.debhelper
	rm -rf debian/fruitnanny-api
	rm -f debian/debhelper-build-stamp
	rm -f debian/fruitnanny-api.*.debhelper
	rm -f debian/fruitnanny-api.substvars

deb:
	$(DEB_BUILD)

crossdeb:
	CONFIG_SITE=/etc/dpkg-cross/cross-config.armhf  DEB_BUILD_OPTIONS=nocheck $(DEB_BUILD) -aarmhf -Pcross,nocheck
