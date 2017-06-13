package wifi

import (
	"fmt"
	"runtime"
	"net"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/genetlink"
)

var (
	// errUnimplemented is returned by all functions on platforms that
	// do not have package wifi implemented.
	errUnimplemented = fmt.Errorf("package wifi not implemented on %s/%s",
		runtime.GOOS, runtime.GOARCH)
)

// A Client is a type which can access WiFi device actions and statistics
// using operating system-specific operations.
type Client struct {
	c osClient
}

// New creates a new Client.
func New() (*Client, error) {
	c, err := newClient()
	if err != nil {
		return nil, err
	}

	return &Client{
		c: c,
	}, nil
}

// Close releases resources used by a Client.
func (c *Client) Close() error {
	return c.c.Close()
}

// Interfaces returns a list of the system's WiFi network interfaces.
func (c *Client) Interfaces() ([]*Interface, error) {
	return c.c.Interfaces()
}

// BSS retrieves the BSS associated with a WiFi interface.
func (c *Client) BSS(ifi *Interface) (*BSS, error) {
	return c.c.BSS(ifi)
}

// StationInfo retrieves station statistics about a WiFi interface.
func (c *Client) StationInfo(ifi *Interface) (*StationInfo, error) {
	return c.c.StationInfo(ifi)
}

// Scan perform an active scan for available wireless networks
func (c *Client) Scan(ifi *Interface) (*ScanResult, error) {
	return c.c.Scan(ifi)
}

// Phys retrieve all physical devices available on the system
func (c *Client) Phys() ([]*Wiphy, error) {
	return c.c.Phys()
}

func (c *Client) InterfaceAdd(iftype InterfaceType, ifname string,
	ifhwaddr net.HardwareAddr, flags *InterfaceFlags, dev WifiDevice) (*Interface, error) {
	return c.c.InterfaceAdd(iftype, ifname, ifhwaddr, flags, dev)
}

func (c *Client) InterfaceDel(ifi *Interface) error {
	return c.c.InterfaceDel(ifi)
}

func (c *Client) InterfaceMeshJoin(ifi *Interface, minfos *MeshBasicInfo,
	meshparams map[string]uint32) error {
	return c.c.InterfaceMeshJoin(ifi, minfos, meshparams)
}

func (c *Client) InterfaceMeshLeave(ifi *Interface) error {
	return c.c.InterfaceMeshLeave(ifi)
}

func (c *Client) InterfaceMeshGetConfig(ifi *Interface) error {
	return c.c.InterfaceMeshGetConfig(ifi)
}

func (c *Client) Receive() ([]genetlink.Message, []netlink.Message, error) {
	return c.c.Receive()
}

func (c *Client) ResolveGroupName(name string) (uint32, error) {
	return c.c.ResolveGroupName(name)
}
func (c *Client) JoinGroup(name string, ID uint32) error {
	return c.c.JoinGroup(name, ID)
}
func (c *Client) LeaveGroup(name string) error {
	return c.c.LeaveGroup(name)
}

// An osClient is the operating system-specific implementation of Client.
type osClient interface {
	Close() error
	Interfaces() ([]*Interface, error)
	BSS(ifi *Interface) (*BSS, error)
	StationInfo(ifi *Interface) (*StationInfo, error)
	Scan(ifi *Interface) (*ScanResult, error)
	Phys() ([]*Wiphy, error)
	InterfaceAdd(iftype InterfaceType, ifname string,
		ifhwaddr net.HardwareAddr, flags *InterfaceFlags, dev WifiDevice) (*Interface, error)
	InterfaceDel(ifi *Interface) error
	InterfaceMeshJoin(ifi *Interface, minfos *MeshBasicInfo,
		meshparams map[string]uint32) error
	InterfaceMeshLeave(ifi *Interface) error
	InterfaceMeshGetConfig(ifi *Interface) error
	Receive() ([]genetlink.Message, []netlink.Message, error)
	ResolveGroupName(name string) (uint32, error)
	JoinGroup(name string, ID uint32) error
	LeaveGroup(name string) error
}
