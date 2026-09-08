// SPDX-License-Identifier: BSD-3-Clause

package smb

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Share types and flags a TREE_CONNECT response carries.
const (
	shareTypeDisk uint8 = 0x01

	shareFlagManualCaching uint32 = 0x00000000

	// The access mask a client is granted on the share itself. A read-only
	// share is refused the write bits HERE, so a file manager greys out the
	// actions rather than offering them and failing later.
	accessRead  uint32 = 0x00120089 // read data | read ea | read attributes | read control | synchronize
	accessWrite uint32 = 0x00120116 // write data | append | write ea | write attributes
	accessAll   uint32 = 0x001F01FF
)

// treeConnect answers \\server\share by name.
//
// The path arrives as UTF-16, absolute and with the host in it. Only the last
// element is the share, and the comparison is caseless -- \\HOST\Disk and
// \\host\disk are the same share, and a client will use whichever the person
// typed.
func (c *conn) treeConnect(h header, body []byte, msg []byte) ([]byte, error) {
	if c.session(h) == nil {
		return errorResponse(h, statusUserSessionDeleted), nil
	}
	if len(body) < 8 {
		return nil, fmt.Errorf("smb: TREE_CONNECT body of %d bytes is too short", len(body))
	}
	off := int(binary.LittleEndian.Uint16(body[4:]))
	n := int(binary.LittleEndian.Uint16(body[6:]))
	if off < 0 || n < 0 || off+n > len(msg) {
		return nil, fmt.Errorf("smb: the share path is not inside the message")
	}
	path := fromUTF16le(msg[off : off+n])
	name := path
	if i := strings.LastIndex(path, `\`); i >= 0 {
		name = path[i+1:]
	}
	sh := c.srv.shareByName(name)
	if sh == nil {
		// BAD_NETWORK_NAME is what a client turns into "the share does not
		// exist" rather than "the server is broken".
		return errorResponse(h, statusBadNetworkName), nil
	}
	c.nextTree++
	tid := c.nextTree
	c.trees[tid] = sh

	access := accessAll
	if sh.ro {
		access = accessRead
	}
	h.treeID = tid
	b := append(responseTo(h, statusSuccess), make([]byte, 16)...)
	rb := b[headerLen:]
	binary.LittleEndian.PutUint16(rb[0:], 16)
	rb[2] = shareTypeDisk
	binary.LittleEndian.PutUint32(rb[4:], shareFlagManualCaching)
	binary.LittleEndian.PutUint32(rb[8:], 0) // capabilities: none of the cluster ones
	binary.LittleEndian.PutUint32(rb[12:], access)
	return b, nil
}

// tree returns the share a message is addressed to.
func (c *conn) tree(h header) *share {
	return c.trees[h.treeID]
}
