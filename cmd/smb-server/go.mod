// A module of its own, so the library stays what it is: one dependency, the
// go-filesystems interface. A command has to pull in drivers to open an image,
// and those would otherwise land in the go.mod of everyone who imports the
// server.
module github.com/go-filesystems/smb/cmd/smb-server

go 1.26.4

require (
	github.com/go-filesystems/detect v0.1.0
	github.com/go-filesystems/exfat v0.3.0
	github.com/go-filesystems/ext4 v0.2.0
	github.com/go-filesystems/fat32 v0.3.0
	github.com/go-filesystems/hfsplus v0.2.0
	github.com/go-filesystems/interface v0.3.0
	github.com/go-filesystems/iso9660 v0.2.0
	github.com/go-filesystems/ntfs v0.1.0
	github.com/go-filesystems/smb v0.0.0
	github.com/go-filesystems/squashfs v0.2.1
	github.com/hashicorp/hcl/v2 v2.24.0
)

require (
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/anchore/go-lzo v0.1.0 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/go-volumes/gpt v0.0.0-20260622072431-e1d6ba3b531c // indirect
	github.com/go-volumes/safeio v0.0.0-20260831125406-d8f54b2890d4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.22 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/zclconf/go-cty v1.16.3 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
)

replace github.com/go-filesystems/smb => ../..
