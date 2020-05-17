package api

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/pkg/errors"
)

type NetworkManager struct {
	conn     *dbus.Conn
	manager  dbus.BusObject
	settings dbus.BusObject
	device   dbus.BusObject

	wpaIface dbus.BusObject
}

type Connection struct {
	Type        string  `json:"type"`
	Id          string  `json:"id"`
	Name        string  `json:"name"`
	Password    *string `json:"-"` // Do not export password via REST API
	Ssid        string  `json:"ssid"`
	Autoconnect bool    `json:"autoconnect"`
	Priority    int32   `json:"priority"`
	path        dbus.ObjectPath
}

func (c *Connection) IsHotspot() bool {
	return c.Type == "hotspot"
}

type AccessPoint struct {
	Ssid     string `json:"ssid"`
	Strength uint8  `json:"strength"`
	Mode     string `json:"mode"`
	Rsn      bool   `json:"rsn"`
	path     dbus.ObjectPath
}

// 802.11 access point flags.
const (
	// access point has no special capabilities
	NM_802_11_AP_FLAGS_NONE = 0x00000000

	// access point requires authentication and encryption (usually means WEP)
	NM_802_11_AP_FLAGS_PRIVACY = 0x00000001

	// access point supports some WPS method
	NM_802_11_AP_FLAGS_WPS = 0x00000002

	// access point supports push-button WPS
	NM_802_11_AP_FLAGS_WPS_PBC = 0x00000004

	// access point supports PIN-based WPS
	NM_802_11_AP_FLAGS_WPS_PIN = 0x00000008
)

// 802.11 access point security and authentication flags. These flags describe
// the current security requirements of an access point as determined from the
// access point's beacon.
const (
	// the access point has no special security requirements
	NM_802_11_AP_SEC_NONE = 0x00000000

	// 40/64-bit WEP is supported for pairwise/unicast encryption
	NM_802_11_AP_SEC_PAIR_WEP40 = 0x00000001

	// 104/128-bit WEP is supported for pairwise/unicast encryption
	NM_802_11_AP_SEC_PAIR_WEP104 = 0x00000002

	// TKIP is supported for pairwise/unicast encryption
	NM_802_11_AP_SEC_PAIR_TKIP = 0x00000004

	// AES/CCMP is supported for pairwise/unicast encryption
	NM_802_11_AP_SEC_PAIR_CCMP = 0x00000008

	// 40/64-bit WEP is supported for group/broadcast encryption
	NM_802_11_AP_SEC_GROUP_WEP40 = 0x00000010

	// 104/128-bit WEP is supported for group/broadcast encryption
	NM_802_11_AP_SEC_GROUP_WEP104 = 0x00000020

	// TKIP is supported for group/broadcast encryption
	NM_802_11_AP_SEC_GROUP_TKIP = 0x00000040

	// AES/CCMP is supported for group/broadcast encryption
	NM_802_11_AP_SEC_GROUP_CCMP = 0x00000080

	// WPA/RSN Pre-Shared Key encryption is supported
	NM_802_11_AP_SEC_KEY_MGMT_PSK = 0x00000100

	// 802.1x authentication and key management is supported
	NM_802_11_AP_SEC_KEY_MGMT_802_1X = 0x00000200

	// WPA/RSN Simultaneous Authentication of Equals is supported
	NM_802_11_AP_SEC_KEY_MGMT_SAE = 0x00000400
)

type Checkpoint struct {
	Id              uint   `json:"id"`
	Created         int64  `json:"created"`
	RollbackTimeout uint32 `json:"rollbackTimeout"`
}

const (
	NmCheckpointCreateFlagNone uint32 = 0

	// when creating a new checkpoint, destroy all existing ones.
	NmCheckpointCreateFlagDestroyAll uint32 = 0x01

	// upon rollback, delete any new connection added after the checkpoint
	// (Since: 1.6)
	NmCheckpointCreateFlagDeleteNewConnections uint32 = 0x02

	// upon rollback, disconnect any new device appeared after the checkpoint
	// (Since: 1.6)
	NmCheckpointCreateFlagDisconnectNewDevices uint32 = 0x04

	// by default, creating a checkpoint fails if there are already existing
	// checkpoints that reference the same devices. With this flag, creation of
	// such checkpoints is allowed, however, if an older checkpoint that
	// references overlapping devices gets rolled back, it will automatically
	// destroy this checkpoint during rollback. This allows to create several
	// overlapping checkpoints in parallel, and rollback to them at will. With
	// the special case that rolling back to an older checkpoint will invalidate
	// all overlapping younger checkpoints. This opts-in that the checkpoint can
	// be automatically destroyed by the rollback of an older checkpoint.
	// (Since: 1.12)
	NmCheckpointCreateFlagAllowOverlapping uint32 = 0x08
)

type Settings map[string]map[string]dbus.Variant

func (c *Checkpoint) Path() dbus.ObjectPath {
	return dbus.ObjectPath(fmt.Sprintf(
		"/org/freedesktop/NetworkManager/Checkpoint/%d",
		c.Id,
	))
}

func (nm *NetworkManager) Close() {
	nm.conn.Close()
}

func NewNetworkManager(ifname string) (*NetworkManager, error) {
	// conn, err := dbus.Connect(
	//  "tcp:host="+host+",port="+port,
	//  dbus.WithAuth(dbus.AuthAnonymous()),
	// )

	// conn, err := dbus.SystemBus()
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, err
	}
	if err = conn.Auth(nil); err != nil {
		conn.Close()
		return nil, err
	}
	if err = conn.Hello(); err != nil {
		conn.Close()
		return nil, err
	}

	manager := conn.Object(
		"org.freedesktop.NetworkManager",
		"/org/freedesktop/NetworkManager",
	)

	settings := conn.Object(
		"org.freedesktop.NetworkManager",
		"/org/freedesktop/NetworkManager/Settings",
	)

	var devicePath dbus.ObjectPath
	err = manager.Call(
		"org.freedesktop.NetworkManager.GetDeviceByIpIface",
		0,
		ifname,
	).Store(&devicePath)
	if err != nil {
		return nil, err
	}
	device := conn.Object(
		"org.freedesktop.NetworkManager",
		devicePath,
	)

	var ifaceObjectPath dbus.ObjectPath
	err = conn.Object(
		"fi.w1.wpa_supplicant1",
		"/fi/w1/wpa_supplicant1",
	).Call(
		"fi.w1.wpa_supplicant1.GetInterface",
		0,
		ifname,
	).Store(&ifaceObjectPath)
	if err != nil {
		return nil, err
	}

	wpaIface := conn.Object(
		"fi.w1.wpa_supplicant1",
		ifaceObjectPath,
	)

	return &NetworkManager{
		conn:     conn,
		manager:  manager,
		settings: settings,
		device:   device,
		wpaIface: wpaIface,
	}, nil
}

func (nm *NetworkManager) readConnectionByPath(path dbus.ObjectPath) (*Connection, error) {
	settings, err := nm.fetchConnectionSettings(path)
	if err != nil {
		return nil, err
	}
	connection := (*settings)["connection"]

	// Filter wifi connections
	t := connection["type"].Value().(string)
	if t != "802-11-wireless" {
		return nil, fmt.Errorf(
			"Expected connection type \"802-11-wireless\", got %q",
			t,
		)
	}

	autoconnect := true
	if val, ok := connection["autoconnect"]; ok {
		autoconnect = val.Value().(bool)
	}

	priority := int32(0)
	if val, ok := connection["autoconnect-priority"]; ok {
		priority = val.Value().(int32)
	}

	wifi := (*settings)["802-11-wireless"]

	// Only consider networks in "infrastructure" mode. There is only one hotspot
	// connection which is managed by FruitNanny.
	mode, ok := wifi["mode"].Value().(string)
	if !ok {
		mode = "infrastructure"
	}

	// Fetch wifi security settings
	secrets, err := nm.fetchWifiSecrets(path)
	if err != nil {
		return nil, err
	}
	security := (*secrets)["802-11-wireless-security"]

	typeStr := "wifi"
	if mode != "infrastructure" {
		typeStr = "hotspot"
	}

	var password *string
	if psk, ok := security["psk"].Value().(string); ok {
		password = &psk
	}

	return &Connection{
		Type:        typeStr,
		Id:          connection["uuid"].Value().(string),
		Name:        connection["id"].Value().(string),
		Password:    password,
		Ssid:        string(wifi["ssid"].Value().([]byte)),
		Autoconnect: autoconnect,
		Priority:    priority,
		path:        path,
	}, nil
}

func (nm *NetworkManager) fetchConnectionSettings(path dbus.ObjectPath) (*Settings, error) {
	var settings Settings
	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		path,
	).Call(
		"org.freedesktop.NetworkManager.Settings.Connection.GetSettings",
		0,
	).Store(&settings)
	if err != nil {
		return nil, errors.Wrap(
			err,
			"Failed to fetch connection settings",
		)
	}
	return &settings, nil
}

func (nm *NetworkManager) fetchWifiSecrets(path dbus.ObjectPath) (*Settings, error) {
	var secrets Settings
	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		path,
	).Call(
		"org.freedesktop.NetworkManager.Settings.Connection.GetSecrets",
		0,
		"802-11-wireless-security",
	).Store(&secrets)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to fetch connection secrets")
	}
	return &secrets, nil
}

func (nm *NetworkManager) ListConnections() []Connection {
	var paths []dbus.ObjectPath
	connections := []Connection{}
	err := nm.settings.Call(
		"org.freedesktop.NetworkManager.Settings.ListConnections",
		0,
	).Store(&paths)
	if err != nil {
		log.Println("Failed to list connections:", err)
		return connections
	}
	for _, path := range paths {
		connection, err := nm.readConnectionByPath(path)
		if err != nil {
			log.Println(err)
		} else if !connection.IsHotspot() {
			// Ignore hotspot connection
			connections = append(connections, *connection)
		}
	}

	return connections
}

func (nm *NetworkManager) ReadConnection(id string) *Connection {
	var connectionPath dbus.ObjectPath
	err := nm.settings.Call(
		"org.freedesktop.NetworkManager.Settings.GetConnectionByUuid",
		0,
		id,
	).Store(&connectionPath)
	if err != nil {
		log.Println("Failed to fetch connection:", err)
		return nil
	}
	connection, err := nm.readConnectionByPath(connectionPath)
	if err != nil {
		log.Println(err)
		return nil
	}
	// Ignore hotspot connection
	if connection.IsHotspot() {
		return nil
	}
	return connection

}

func (nm *NetworkManager) DeleteConnection(connection *Connection) error {
	if nm.isActiveConnection(connection) {
		log.Println("Cannot delete active connection")
		return fmt.Errorf("Connection is active")
	}

	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		connection.path,
	).Call(
		"org.freedesktop.NetworkManager.Settings.Connection.Delete",
		0,
	).Err
	if err != nil {
		return err
	}
	log.Println("Deleted connection", connection.Id)
	return nil
}

func (nm *NetworkManager) isActiveConnection(connection *Connection) bool {
	activeConnectionPaths, err := nm.manager.GetProperty(
		"org.freedesktop.NetworkManager.ActiveConnections",
	)
	if err != nil {
		panic(err)
	}
	for _, path := range activeConnectionPaths.Value().([]dbus.ObjectPath) {
		connectionPath, err := nm.conn.Object(
			"org.freedesktop.NetworkManager",
			path,
		).GetProperty(
			"org.freedesktop.NetworkManager.Connection.Active.Connection",
		)
		if err != nil {
			log.Println("Failed to fetch connection:", connectionPath)
		} else if connectionPath.Value().(dbus.ObjectPath) == connection.path {
			return true
		}
	}
	return false
}

func (nm *NetworkManager) ListAccessPoints() []AccessPoint {
	accessPoints := []AccessPoint{}

	if err := nm.scan(); err != nil {
		log.Println(err)
		return accessPoints
	}

	bssPaths, err := nm.wpaIface.GetProperty(
		"fi.w1.wpa_supplicant1.Interface.BSSs",
	)
	if err != nil {
		log.Println("Failed to fetch BSSs:", err)
		return accessPoints
	}

	for _, bssPath := range bssPaths.Value().([]dbus.ObjectPath) {
		accessPoint := nm.readAccessPointByBSSPath(bssPath)
		if accessPoint != nil {
			accessPoints = append(accessPoints, *accessPoint)
		}
	}

	sort.Slice(accessPoints, func(i, j int) bool {
		return accessPoints[i].Strength > accessPoints[j].Strength
	})

	return accessPoints
}

func (nm *NetworkManager) scan() error {
	timeout := 3 * time.Second

	opts := []dbus.MatchOption{
		dbus.WithMatchObjectPath(nm.wpaIface.Path()),
		dbus.WithMatchInterface("fi.w1.wpa_supplicant1.Interface"),
		dbus.WithMatchMember("ScanDone"),
	}
	if err := nm.conn.AddMatchSignal(opts...); err != nil {
		return errors.Wrap(err, "Failed to add match signal")
	}
	done := make(chan error, 1)
	signals := make(chan *dbus.Signal)
	nm.conn.Signal(signals)

	unregister := func() {
		nm.conn.RemoveSignal(signals)
		nm.conn.RemoveMatchSignal(opts...)
	}
	defer unregister()

	go func() {
		for {
			select {
			case signal := <-signals:
				success := signal.Body[0].(bool)
				if !success {
					done <- fmt.Errorf("Scan failed")
				} else {
					done <- nil
				}
				return

			case <-time.After(timeout):
				done <- nil
				scanning, err := nm.wpaIface.GetProperty(
					"fi.w1.wpa_supplicant1.Interface.Scanning",
				)
				if err != nil {
					done <- errors.Wrap(
						err,
						"Failed to read interface state",
					)
				}
				if scanning.Value().(bool) {
					done <- fmt.Errorf("Timeout")
					return
				}
				done <- nil
				return
			}
		}
	}()

	err := nm.wpaIface.Call(
		"fi.w1.wpa_supplicant1.Interface.Scan",
		0,
		map[string]dbus.Variant{
			"Type": dbus.MakeVariant("passive"),
		},
	).Store()
	if err != nil {
		return errors.Wrap(err, "Failed to scan access points")
	}

	return <-done
}

func (nm *NetworkManager) readAccessPointByBSSPath(path dbus.ObjectPath) *AccessPoint {
	var properties map[string]dbus.Variant
	err := nm.conn.Object(
		"fi.w1.wpa_supplicant1",
		path,
	).Call(
		"org.freedesktop.DBus.Properties.GetAll",
		0,
		"fi.w1.wpa_supplicant1.BSS",
	).Store(&properties)
	if err != nil {
		log.Println("Failed to fetch BSS properties:", err)
		return nil
	}

	rsn := properties["RSN"].Value().(map[string]dbus.Variant)
	signal := properties["Signal"].Value().(int16)

	return &AccessPoint{
		Ssid:     string(properties["SSID"].Value().([]byte)),
		Strength: signalToPercentage(signal),
		Mode:     properties["Mode"].Value().(string),
		Rsn:      len(rsn) != 0,
		path:     path,
	}

}

func signalToPercentage(dbm int16) uint8 {
	const (
		max = 1.5440680443502757 // -35 dBm  -> 100%
		min = 2.0                // -100 dBm -> 1%
	)
	if dbm >= 0 {
		return 100
	}
	exponent := math.Log10(float64(-dbm))
	linearized := 1.0 - (exponent-max)/(min-max)

	return uint8(100 * math.Min(math.Max(linearized, 0.01), 1.0))
}

const (
	// the device's state is unknown
	NmDeviceStateUnknown uint32 = 0

	// the device is recognized, but not managed by NetworkManager
	NmDeviceStateUnmanaged uint32 = 10

	// the device is managed by NetworkManager, but is not available for use.
	// Reasons may include the wireless switched off, missing firmware, no
	// ethernet carrier, missing supplicant or modem manager, etc.
	NmDeviceStateUnavailable uint32 = 20

	// the device can be activated, but is currently idle and not connected to a
	// network.
	NmDeviceStateDisconnected uint32 = 30

	// the device is preparing the connection to the network. This may include
	// operations like changing the MAC address, setting physical link
	// properties, and anything else required to connect to the requested
	// network.
	NmDeviceStatePrepare uint32 = 40

	// the device is connecting to the requested network. This may include
	// operations like associating with the Wi-Fi AP, dialing the modem,
	// connecting to the remote Bluetooth device, etc.
	NmDeviceStateConfig uint32 = 50

	// the device requires more information to continue connecting to the
	// requested network. This includes secrets like WiFi passphrases, login
	// passwords, PIN codes, etc.
	NmDeviceStateNeedAuth uint32 = 60

	// the device is requesting IPv4 and/or IPv6 addresses and routing
	// information from the network.
	NmDeviceStateIpConfig uint32 = 70

	// the device is checking whether further action is required for the
	// requested network connection. This may include checking whether only local
	// network access is available, whether a captive portal is blocking access
	// to the Internet, etc.
	NmDeviceStateIpCheck uint32 = 80

	// the device is waiting for a secondary connection (like a VPN) which must
	// activated before the device can be activated
	NmDeviceStateSecondaries uint32 = 90

	// the device has a network connection, either local or global.
	NmDeviceStateActivated uint32 = 100

	// a disconnection from the current network connection was requested, and the
	// device is cleaning up resources used for that connection. The network
	// connection may still be valid.
	NmDeviceStateDeactivating uint32 = 110

	// the device failed to connect to the requested network and is cleaning up
	// the connection request
	NmDeviceStateFailed uint32 = 120
)

func (nm *NetworkManager) IsConnected() bool {
	state, err := nm.device.GetProperty(
		"org.freedesktop.NetworkManager.Device.State",
	)
	if err != nil {
		log.Println("Failed to fetch device state:", err)
		return false
	}

	return state.Value().(uint32) == NmDeviceStateActivated
}

func (nm *NetworkManager) Disconnect() error {
	const timeout = 3 * time.Second

	if !nm.IsConnected() {
		return nil
	}

	done := make(chan error, 1)
	go nm.listenForDeviceState(done, NmDeviceStateDisconnected, timeout)

	err := nm.device.Call(
		"org.freedesktop.NetworkManager.Device.Disconnect",
		0,
	).Err
	if err != nil {
		return errors.Wrap(err, "Disconnect failed")
	}
	return <-done
}

func (nm *NetworkManager) ReadActiveConnection() *Connection {
	activeConnectionPath, err := nm.device.GetProperty(
		"org.freedesktop.NetworkManager.Device.ActiveConnection",
	)
	if err != nil {
		log.Println("Failed to fetch active connection:", err)
		return nil
	}
	// Device is currently not connected
	if activeConnectionPath.Value().(dbus.ObjectPath) == "/" {
		return nil
	}
	connectionPath, err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		activeConnectionPath.Value().(dbus.ObjectPath),
	).GetProperty(
		"org.freedesktop.NetworkManager.Connection.Active.Connection",
	)
	if err != nil {
		log.Println("Failed to fetch activate connection:", err)
		return nil
	}
	connection, err := nm.readConnectionByPath(
		connectionPath.Value().(dbus.ObjectPath),
	)
	if err != nil {
		log.Println("Failed to fetch connection:", err)
		return nil
	}
	return connection
}

func (nm *NetworkManager) Connect(ssid string, password *string) (*Connection, error) {
	// const rollbackTimeout = 15 * time.Second
	const waitTimeout = 10 * time.Second

	// checkpoint, err := nm.CreateCheckpoint(rollbackTimeout, false)
	// if err != nil {
	//     return nil, err
	// }

	settings := Settings{
		"connection": map[string]dbus.Variant{
			"id": dbus.MakeVariant(ssid),
		},
		"802-11-wireless": map[string]dbus.Variant{
			"mode": dbus.MakeVariant("infrastructure"),
			"ssid": dbus.MakeVariant([]byte(ssid)),
		},
	}

	if password != nil {
		settings["802-11-wireless-security"] = map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant("wpa-psk"),
			"psk":      dbus.MakeVariant(*password),
		}
	}

	var connectionPath dbus.ObjectPath
	var activeConnectionPath dbus.ObjectPath
	err := nm.manager.Call(
		"org.freedesktop.NetworkManager.AddAndActivateConnection",
		0,
		settings,
		nm.device.Path(),
		dbus.ObjectPath("/"),
	).Store(&connectionPath, &activeConnectionPath)
	if err != nil {
		// nm.Rollback(checkpoint)
		return nil, errors.Wrap(err, "Failed to connect")
	}

	err = nm.waitForDeviceState(NmDeviceStateActivated, waitTimeout)
	if err != nil {
		// nm.Rollback(checkpoint)
		return nil, errors.Wrap(err, "Device not connected")
	}

	// nm.DeleteCheckpoint(checkpoint)
	return nm.readConnectionByPath(connectionPath)
}

func isAccessPointNotFound(err error) bool {
	type accessPoint interface {
		AccessPointNotFound() bool
	}
	a, ok := err.(accessPoint)
	return ok && a.AccessPointNotFound()
}

type accessPointNotFound struct {
	ssid string
}

func (e *accessPointNotFound) Error() string {
	return fmt.Sprintf("Access point %q not found", e.ssid)
}

const (
	UpdateFlagToDisk           uint32 = 0x1
	UpdateFlagBlockAutoconnect uint32 = 0x20
)

func (nm *NetworkManager) UpdateConnection(connection *Connection, name, ssid string, autoconnect bool, priority int32) error {
	settings := Settings{
		"connection": map[string]dbus.Variant{
			"uuid":                 dbus.MakeVariant(connection.Id),
			"id":                   dbus.MakeVariant(name),
			"autoconnect":          dbus.MakeVariant(autoconnect),
			"autoconnect-priority": dbus.MakeVariant(priority),
		},
		"802-11-wireless": map[string]dbus.Variant{
			"mode": dbus.MakeVariant("infrastructure"),
			"ssid": dbus.MakeVariant([]byte(ssid)),
		},
	}

	if connection.Password != nil {
		settings["802-11-wireless-security"] = map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant("wpa-psk"),
			"psk":      dbus.MakeVariant(*connection.Password),
		}
	}

	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		connection.path,
	).Call(
		"org.freedesktop.NetworkManager.Settings.Connection.Update2",
		0,
		settings,
		UpdateFlagToDisk|UpdateFlagBlockAutoconnect,
		map[string]dbus.Variant{},
	).Err
	if err != nil {
		return errors.Wrap(err, "Failed to update connection")
	}

	// Populate connection
	connection.Name = name
	connection.Ssid = ssid
	connection.Autoconnect = autoconnect
	connection.Priority = priority

	return nil
}

func (nm *NetworkManager) UpdateHotspot(hotspot *Hotspot, ssid string, password *string) error {
	settings := Settings{
		"connection": hotspotDefaults["connection"],
		"802-11-wireless": map[string]dbus.Variant{
			"mode": hotspotDefaults["802-11-wireless"]["mode"],
			"band": hotspotDefaults["802-11-wireless"]["band"],
			"ssid": dbus.MakeVariant([]byte(ssid)),
		},
		"ipv4": map[string]dbus.Variant{
			"method": dbus.MakeVariant("shared"),
		},
	}

	if password != nil {
		settings["802-11-wireless-security"] = map[string]dbus.Variant{
			"key-mgmt": dbus.MakeVariant("wpa-psk"),
			"psk":      dbus.MakeVariant(password),
		}
	}

	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		hotspot.path,
	).Call(
		"org.freedesktop.NetworkManager.Settings.Connection.Update2",
		0,
		settings,
		UpdateFlagToDisk|UpdateFlagBlockAutoconnect,
		map[string]dbus.Variant{},
	).Err
	if err != nil {
		return errors.Wrap(err, "Failed to update hotspot")
	}

	// Populate hotspot
	hotspot.Ssid = ssid
	hotspot.Password = password

	return nil
}

func (nm *NetworkManager) ActivateConnection(connection *Connection) error {
	const scanTimeout = 5 * time.Second
	const waitTimeout = 30 * time.Second

	// TODO: Maybe this is not required on the Raspberry because there is not
	//   session-based secret agent?
	var err error
	for i := 0; i < 2; i++ {
		err = nm.manager.Call(
			"org.freedesktop.NetworkManager.ActivateConnection",
			0,
			connection.path,
			nm.device.Path(),
			dbus.ObjectPath("/"),
		).Err
		if err != nil {
			return errors.Wrap(err, "Failed to activate connection")
		}

		err = nm.waitForDeviceState(NmDeviceStateActivated, waitTimeout)
		if err == nil {
			return nil
		}
		if isNoSecretsError(err) {
			log.Println("Supplicant probably disconnected. Retry connection activation")
		} else {
			return err
		}
	}
	return errors.Wrap(err, "Device is not connected")
}

func isNoSecretsError(err error) bool {
	if signal, ok := err.(*deviceStateSignal); ok {
		return signal.reason == NmDeviceStateReasonNoSecrets
	}
	return false
}

type deviceStateSignal struct {
	state  uint32
	reason uint32
}

var deviceStateMessages = map[uint32]string{
	NmDeviceStateUnknown:      "Unknown",
	NmDeviceStateUnmanaged:    "Unmanaged",
	NmDeviceStateUnavailable:  "Unavailable",
	NmDeviceStateDisconnected: "Disconnected",
	NmDeviceStatePrepare:      "Prepare",
	NmDeviceStateConfig:       "Config",
	NmDeviceStateNeedAuth:     "Need auth",
	NmDeviceStateIpConfig:     "IP config",
	NmDeviceStateIpCheck:      "IP check",
	NmDeviceStateSecondaries:  "Secondaries",
	NmDeviceStateActivated:    "Activated",
	NmDeviceStateDeactivating: "Deactivating",
	NmDeviceStateFailed:       "Failed",
}

const (
	// No reason given
	NmDeviceStateReasonNone uint32 = 0

	// Unknown error
	NmDeviceStateReasonUnknown uint32 = 1

	// Device is now managed
	NmDeviceStateReasonNowManaged uint32 = 2

	// Device is now unmanaged
	NmDeviceStateReasonNowUnmanaged uint32 = 3

	// The device could not be readied for configuration
	NmDeviceStateReasonConfigFailed uint32 = 4

	// IP configuration could not be reserved (no available address, timeout, etc)
	NmDeviceStateReasonIpConfigUnavailable uint32 = 5

	// The IP config is no longer valid
	NmDeviceStateReasonIpConfigExpired uint32 = 6

	// Secrets were required, but not provided
	NmDeviceStateReasonNoSecrets uint32 = 7

	// 802.1x supplicant disconnected
	NmDeviceStateReasonSupplicantDisconnect uint32 = 8

	// 802.1x supplicant configuration failed
	NmDeviceStateReasonSupplicantConfigFailed uint32 = 9

	// 802.1x supplicant failed
	NmDeviceStateReasonSupplicantFailed uint32 = 10

	// 802.1x supplicant took too long to authenticate
	NmDeviceStateReasonSupplicantTimeout uint32 = 11

	// PPP service failed to start
	NmDeviceStateReasonPppStartFailed uint32 = 12

	// PPP service disconnected
	NmDeviceStateReasonPppDisconnect uint32 = 13

	// PPP failed
	NmDeviceStateReasonPppFailed uint32 = 14

	// DHCP client failed to start
	NmDeviceStateReasonDhcpStartFailed uint32 = 15

	// DHCP client error
	NmDeviceStateReasonDhcpError uint32 = 16

	// DHCP client failed
	NmDeviceStateReasonDhcpFailed uint32 = 17

	// Shared connection service failed to start
	NmDeviceStateReasonSharedStartFailed uint32 = 18

	// Shared connection service failed
	NmDeviceStateReasonSharedFailed uint32 = 19

	// AutoIP service failed to start
	NmDeviceStateReasonAutoipStartFailed uint32 = 20

	// AutoIP service error
	NmDeviceStateReasonAutoipError uint32 = 21

	// AutoIP service failed
	NmDeviceStateReasonAutoipFailed uint32 = 22

	// The line is busy
	NmDeviceStateReasonModemBusy uint32 = 23

	// No dial tone
	NmDeviceStateReasonModemNoDialTone uint32 = 24

	// No carrier could be established
	NmDeviceStateReasonModemNoCarrier uint32 = 25

	// The dialing request timed out
	NmDeviceStateReasonModemDialTimeout uint32 = 26

	// The dialing attempt failed
	NmDeviceStateReasonModemDialFailed uint32 = 27

	// Modem initialization failed
	NmDeviceStateReasonModemInitFailed uint32 = 28

	// Failed to select the specified APN
	NmDeviceStateReasonGsmApnFailed uint32 = 29

	// Not searching for networks
	NmDeviceStateReasonGsmRegistrationNotSearching uint32 = 30

	// Network registration denied
	NmDeviceStateReasonGsmRegistrationDenied uint32 = 31

	// Network registration timed out
	NmDeviceStateReasonGsmRegistrationTimeout uint32 = 32

	// Failed to register with the requested network
	NmDeviceStateReasonGsmRegistrationFailed uint32 = 33

	// PIN check failed
	NmDeviceStateReasonGsmPinCheckFailed uint32 = 34

	// Necessary firmware for the device may be missing
	NmDeviceStateReasonFirmwareMissing uint32 = 35

	// The device was removed
	NmDeviceStateReasonRemoved uint32 = 36

	// NetworkManager went to sleep
	NmDeviceStateReasonSleeping uint32 = 37

	// The device's active connection disappeared
	NmDeviceStateReasonConnectionRemoved uint32 = 38

	// Device disconnected by user or client
	NmDeviceStateReasonUserRequested uint32 = 39

	// Carrier/link changed
	NmDeviceStateReasonCarrier uint32 = 40

	// The device's existing connection was assumed
	NmDeviceStateReasonConnectionAssumed uint32 = 41

	// The supplicant is now available
	NmDeviceStateReasonSupplicantAvailable uint32 = 42

	// The modem could not be found
	NmDeviceStateReasonModemNotFound uint32 = 43

	// The Bluetooth connection failed or timed out
	NmDeviceStateReasonBtFailed uint32 = 44

	// GSM Modem's SIM Card not inserted
	NmDeviceStateReasonGsmSimNotInserted uint32 = 45

	// GSM Modem's SIM Pin required
	NmDeviceStateReasonGsmSimPinRequired uint32 = 46

	// GSM Modem's SIM Puk required
	NmDeviceStateReasonGsmSimPukRequired uint32 = 47

	// GSM Modem's SIM wrong
	NmDeviceStateReasonGsmSimWrong uint32 = 48

	// InfiniBand device does not support connected mode
	NmDeviceStateReasonInfinibandMode uint32 = 49

	// A dependency of the connection failed
	NmDeviceStateReasonDependencyFailed uint32 = 50

	// Problem with the RFC 2684 Ethernet over ADSL bridge
	NmDeviceStateReasonBr2684Failed uint32 = 51

	// ModemManager not running
	NmDeviceStateReasonModemManagerUnavailable uint32 = 52

	// The Wi-Fi network could not be found
	NmDeviceStateReasonSsidNotFound uint32 = 53

	// A secondary connection of the base connection failed
	NmDeviceStateReasonSecondaryConnectionFailed uint32 = 54

	// DCB or FCoE setup failed
	NmDeviceStateReasonDcbFcoeFailed uint32 = 55

	// teamd control failed
	NmDeviceStateReasonTeamdControlFailed uint32 = 56

	// Modem failed or no longer available
	NmDeviceStateReasonModemFailed uint32 = 57

	// Modem now ready and available
	NmDeviceStateReasonModemAvailable uint32 = 58

	// SIM PIN was incorrect
	NmDeviceStateReasonSimPinIncorrect uint32 = 59

	// New connection activation was enqueued
	NmDeviceStateReasonNewActivation uint32 = 60

	// the device's parent changed
	NmDeviceStateReasonParentChanged uint32 = 61

	// the device parent's management changed
	NmDeviceStateReasonParentManagedChanged uint32 = 62

	// problem communicating with Open vSwitch database
	NmDeviceStateReasonOvsdbFailed uint32 = 63

	// a duplicate IP address was detected
	NmDeviceStateReasonIpAddressDuplicate uint32 = 64

	// The selected IP method is not supported
	NmDeviceStateReasonIpMethodUnsupported uint32 = 65

	// configuration of SR-IOV parameters failed
	NmDeviceStateReasonSriovConfigurationFailed uint32 = 66

	// The Wi-Fi P2P peer could not be found
	NmDeviceStateReasonPeerNotFound uint32 = 67
)

var deviceStateReasonMessages = map[uint32]string{
	NmDeviceStateReasonNone:                        "none",
	NmDeviceStateReasonUnknown:                     "unknown",
	NmDeviceStateReasonNowManaged:                  "now managed",
	NmDeviceStateReasonNowUnmanaged:                "now unmanaged",
	NmDeviceStateReasonConfigFailed:                "config failed",
	NmDeviceStateReasonIpConfigUnavailable:         "IP config unavailable",
	NmDeviceStateReasonIpConfigExpired:             "IP config expired",
	NmDeviceStateReasonNoSecrets:                   "no secrets",
	NmDeviceStateReasonSupplicantDisconnect:        "supplicant disconnect",
	NmDeviceStateReasonSupplicantConfigFailed:      "supplicant config failed",
	NmDeviceStateReasonSupplicantFailed:            "supplicant failed",
	NmDeviceStateReasonSupplicantTimeout:           "supplicant timeout",
	NmDeviceStateReasonPppStartFailed:              "PPP start failed",
	NmDeviceStateReasonPppDisconnect:               "PPP disconnect",
	NmDeviceStateReasonPppFailed:                   "PPP failed",
	NmDeviceStateReasonDhcpStartFailed:             "DHCP start failed",
	NmDeviceStateReasonDhcpError:                   "DHCP error",
	NmDeviceStateReasonDhcpFailed:                  "DHCP failed",
	NmDeviceStateReasonSharedStartFailed:           "shared start failed",
	NmDeviceStateReasonSharedFailed:                "shared failed",
	NmDeviceStateReasonAutoipStartFailed:           "autoip start failed",
	NmDeviceStateReasonAutoipError:                 "autoip error",
	NmDeviceStateReasonAutoipFailed:                "autoip failed",
	NmDeviceStateReasonModemBusy:                   "modem busy",
	NmDeviceStateReasonModemNoDialTone:             "modem no dial tone",
	NmDeviceStateReasonModemNoCarrier:              "modem no carrier",
	NmDeviceStateReasonModemDialTimeout:            "modem dial timeout",
	NmDeviceStateReasonModemDialFailed:             "modem dial failed",
	NmDeviceStateReasonModemInitFailed:             "modem init failed",
	NmDeviceStateReasonGsmApnFailed:                "GSM apn failed",
	NmDeviceStateReasonGsmRegistrationNotSearching: "GSM registration not searching",
	NmDeviceStateReasonGsmRegistrationDenied:       "GSM registration denied",
	NmDeviceStateReasonGsmRegistrationTimeout:      "GSM registration timeout",
	NmDeviceStateReasonGsmRegistrationFailed:       "GSM registration failed",
	NmDeviceStateReasonGsmPinCheckFailed:           "GSM pin check failed",
	NmDeviceStateReasonFirmwareMissing:             "firmware missing",
	NmDeviceStateReasonRemoved:                     "removed",
	NmDeviceStateReasonSleeping:                    "sleeping",
	NmDeviceStateReasonConnectionRemoved:           "connection removed",
	NmDeviceStateReasonUserRequested:               "user requested",
	NmDeviceStateReasonCarrier:                     "carrier",
	NmDeviceStateReasonConnectionAssumed:           "connection assumed",
	NmDeviceStateReasonSupplicantAvailable:         "supplicant available",
	NmDeviceStateReasonModemNotFound:               "modem not found",
	NmDeviceStateReasonBtFailed:                    "BT failed",
	NmDeviceStateReasonGsmSimNotInserted:           "GSM sim not inserted",
	NmDeviceStateReasonGsmSimPinRequired:           "GSM sim pin required",
	NmDeviceStateReasonGsmSimPukRequired:           "GSM sim puk required",
	NmDeviceStateReasonGsmSimWrong:                 "GSM sim wrong",
	NmDeviceStateReasonInfinibandMode:              "infiniband mode",
	NmDeviceStateReasonDependencyFailed:            "dependency failed",
	NmDeviceStateReasonBr2684Failed:                "Br2684 failed",
	NmDeviceStateReasonModemManagerUnavailable:     "modem manager unavailable",
	NmDeviceStateReasonSsidNotFound:                "SSID not found",
	NmDeviceStateReasonSecondaryConnectionFailed:   "secondary connection failed",
	NmDeviceStateReasonDcbFcoeFailed:               "DCB FCOE failed",
	NmDeviceStateReasonTeamdControlFailed:          "teamd control failed",
	NmDeviceStateReasonModemFailed:                 "modem failed",
	NmDeviceStateReasonModemAvailable:              "modem available",
	NmDeviceStateReasonSimPinIncorrect:             "SIM pin incorrect",
	NmDeviceStateReasonNewActivation:               "new activation",
	NmDeviceStateReasonParentChanged:               "parent changed",
	NmDeviceStateReasonParentManagedChanged:        "parent managed changed",
	NmDeviceStateReasonOvsdbFailed:                 "Ovsdb failed",
	NmDeviceStateReasonIpAddressDuplicate:          "IP address duplicate",
	NmDeviceStateReasonIpMethodUnsupported:         "IP method unsupported",
	NmDeviceStateReasonSriovConfigurationFailed:    "SRIOV configuration failed",
	NmDeviceStateReasonPeerNotFound:                "peer not found",
}

func (s *deviceStateSignal) Error() string {
	if s.reason == NmDeviceStateReasonNone {
		return fmt.Sprintf(
			"[%d] %s",
			s.state,
			deviceStateMessages[s.state],
		)

	}
	return fmt.Sprintf(
		"[%d] %s ([%d] %s)",
		s.state,
		deviceStateMessages[s.state],
		s.reason,
		deviceStateReasonMessages[s.reason],
	)
}

func (nm *NetworkManager) listenForDeviceState(done chan error, expected uint32, timeout time.Duration) {
	opts := []dbus.MatchOption{
		dbus.WithMatchObjectPath(nm.device.Path()),
		dbus.WithMatchInterface("org.freedesktop.NetworkManager.Device"),
		dbus.WithMatchMember("StateChanged"),
	}
	if err := nm.conn.AddMatchSignal(opts...); err != nil {
		done <- errors.Wrap(err, "Failed to add match signal")
	}
	signals := make(chan *dbus.Signal)
	nm.conn.Signal(signals)

	unregister := func() {
		nm.conn.RemoveSignal(signals)
		nm.conn.RemoveMatchSignal(opts...)
	}
	defer unregister()

	for {
		select {
		case signal := <-signals:
			new := signal.Body[0].(uint32)
			reason := signal.Body[2].(uint32)

			stateSignal := deviceStateSignal{
				state:  new,
				reason: reason,
			}
			if new == expected {
				done <- nil
				return
			}
			if new == NmDeviceStateFailed {
				done <- &stateSignal
				return
			}
		case <-time.After(timeout):
			done <- fmt.Errorf("Timeout")
			return
		}
	}

}

func (nm *NetworkManager) waitForDeviceState(expected uint32, timeout time.Duration) error {
	done := make(chan error, 1)

	// Check if device is already in state
	state, err := nm.device.GetProperty(
		"org.freedesktop.NetworkManager.Device.State",
	)
	if err != nil {
		return err
	}
	if state.Value().(uint32) == expected {
		return nil
	}

	go nm.listenForDeviceState(done, expected, timeout)
	return <-done
}

func isCheckpointExists(err error) bool {
	type checkpointExists interface {
		CheckpointExists() bool
	}

	c, ok := err.(checkpointExists)
	return ok && c.CheckpointExists()
}

type checkpointExistsError struct {
}

func (e *checkpointExistsError) CheckpointExists() bool {
	return true
}

func (e *checkpointExistsError) Error() string {
	return "Checkpoint already exists"
}

func (nm *NetworkManager) CreateCheckpoint(rollbackTimeout time.Duration, overwrite bool) (*Checkpoint, error) {
	devices := []dbus.ObjectPath{nm.device.Path()}

	var flags uint32 = NmCheckpointCreateFlagDeleteNewConnections
	if overwrite {
		flags |= NmCheckpointCreateFlagDestroyAll
	}

	var checkpointPath dbus.ObjectPath
	err := nm.manager.Call(
		"org.freedesktop.NetworkManager.CheckpointCreate",
		0,
		devices,
		uint(rollbackTimeout.Seconds()),
		flags,
	).Store(&checkpointPath)
	if err != nil {
		if derr, ok := err.(dbus.DBusError); ok {
			name, _ := derr.DBusError()
			if name == "org.freedesktop.NetworkManager.InvalidArguments" {
				return nil, &checkpointExistsError{}
			}

		}
		return nil, errors.Wrap(err, "Failed to create checkpoint")
	}

	checkpoint, err := nm.readCheckpointByPath(checkpointPath)
	if err != nil {
		nm.manager.Call(
			"org.freedesktop.NetworkManager.CheckpointDestroy",
			0,
			checkpointPath,
		)
		return nil, err
	}

	return checkpoint, err
}

func (nm *NetworkManager) ReadCheckpoint() *Checkpoint {
	checkpointPaths := []dbus.ObjectPath{}
	prop, err := nm.manager.GetProperty(
		"org.freedesktop.NetworkManager.Checkpoints",
	)
	if err != nil {
		if derr, ok := err.(dbus.Error); ok {
			// Older versions of NetworkManager do not have "Checkpoints" property.
			// Iterate over DBus objects.
			if derr.Name == "org.freedesktop.DBus.Error.InvalidArgs" {
				checkpointPaths = nm.iterateCheckpoints()
			} else {
				log.Printf("%s: %s", derr.Name, err)
				return nil
			}
		} else {
			log.Println("Failed to fetch checkpoints:", err)
			return nil
		}
	} else {
		checkpointPaths = prop.Value().([]dbus.ObjectPath)
	}
	// No checkpoints found
	if len(checkpointPaths) == 0 {
		return nil
	}
	if len(checkpointPaths) > 1 {
		log.Println("Warning: found more than one checkpoint")
	}
	checkpoint, err := nm.readCheckpointByPath(checkpointPaths[0])
	if err != nil {
		log.Println("Failed to fetch checkpoint:", err)
		return nil
	}
	return checkpoint
}

func (nm *NetworkManager) iterateCheckpoints() []dbus.ObjectPath {
	checkpointPaths := []dbus.ObjectPath{}

	node, err := introspect.Call(nm.conn.Object(
		"org.freedesktop.NetworkManager",
		"/org/freedesktop/NetworkManager/Checkpoint",
	))
	if err != nil {
		log.Println(err)
		return checkpointPaths
	}
	for _, child := range node.Children {
		path := dbus.ObjectPath(
			fmt.Sprintf("%s/%s", node.Name, child.Name),
		)
		checkpointPaths = append(checkpointPaths, path)
	}

	return checkpointPaths
}

func (nm *NetworkManager) readCheckpointByPath(path dbus.ObjectPath) (*Checkpoint, error) {
	var properties map[string]dbus.Variant
	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		path,
	).Call(
		"org.freedesktop.DBus.Properties.GetAll",
		0,
		"org.freedesktop.NetworkManager.Checkpoint",
	).Store(&properties)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to fetch checkpoint")
	}

	last := string(path)[strings.LastIndex(string(path), "/")+1:]
	id, err := strconv.ParseUint(last, 10, 32)
	if err != nil {
		return nil, errors.Wrapf(
			err,
			"Failed to parse checkpoint path %q",
			string(path),
		)
	}

	return &Checkpoint{
		Id:              uint(id),
		Created:         properties["Created"].Value().(int64),
		RollbackTimeout: properties["RollbackTimeout"].Value().(uint32),
	}, nil
}

func (nm *NetworkManager) DeleteCheckpoint(checkpoint *Checkpoint) {
	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		"/org/freedesktop/NetworkManager",
	).Call(
		"org.freedesktop.NetworkManager.CheckpointDestroy",
		0,
		checkpoint.Path(),
	).Err
	if err != nil {
		log.Println("Failed to delete checkpoint:", err)
	}
}

func (nm *NetworkManager) Rollback(checkpoint *Checkpoint) {
	var results map[string]uint
	err := nm.conn.Object(
		"org.freedesktop.NetworkManager",
		"/org/freedesktop/NetworkManager",
	).Call(
		"org.freedesktop.NetworkManager.CheckpointRollback",
		0,
		checkpoint.Path(),
	).Store(&results)
	if err != nil {
		log.Println("Failed to rollback checkpoint:", err)
	}
}

func clock_boottime() time.Duration {
	const CLOCK_BOOTTIME = 7
	var ts syscall.Timespec

	syscall.Syscall(
		syscall.SYS_CLOCK_GETTIME,
		CLOCK_BOOTTIME,
		uintptr(unsafe.Pointer(&ts)),
		0,
	)

	return time.Duration(ts.Nano())
}

const hotspotUuid = "cc9b2246-f47a-49ec-8fc1-4b77e0e0146c"

var hotspotDefaults = Settings{
	"connection": map[string]dbus.Variant{
		"uuid": dbus.MakeVariant(hotspotUuid),
		"id":   dbus.MakeVariant("FruitNanny Hotspot"),
		"type": dbus.MakeVariant("802-11-wireless"),
	},
	"802-11-wireless": map[string]dbus.Variant{
		// "mode": dbus.MakeVariant("adhoc"),
		"mode": dbus.MakeVariant("ap"),
		"band": dbus.MakeVariant("bg"),
		"ssid": dbus.MakeVariant([]byte("FruitNanny")),
	},
	"802-11-wireless-security": map[string]dbus.Variant{
		"key-mgmt": dbus.MakeVariant("wpa-psk"),
		"psk":      dbus.MakeVariant("fruitnanny"),
	},
	"ipv4": map[string]dbus.Variant{
		"method": dbus.MakeVariant("shared"),
	},
}

type Hotspot struct {
	Type     string  `json:"type"`
	Password *string `json:"password"`
	Ssid     string  `json:"ssid"`
	path     dbus.ObjectPath
}

func (c *Connection) makeHotspot() *Hotspot {
	return &Hotspot{
		Type:     c.Type,
		Password: c.Password,
		Ssid:     c.Ssid,
		path:     c.path,
	}
}

func (nm *NetworkManager) ReadHotspot() (*Hotspot, error) {
	var connectionPath dbus.ObjectPath
	err := nm.settings.Call(
		"org.freedesktop.NetworkManager.Settings.GetConnectionByUuid",
		0,
		hotspotUuid,
	).Store(&connectionPath)
	if err != nil {
		log.Printf("Initialize hotspot connection (%s)", err)
		return nm.createHotspot()
		// return nil, errors.Wrap(err, "Failed to fetch connection")
	}
	connection, err := nm.readConnectionByPath(connectionPath)
	if err != nil {
		return nil, err
	}
	return connection.makeHotspot(), nil
}

func (nm *NetworkManager) createHotspot() (*Hotspot, error) {
	var connectionPath dbus.ObjectPath
	err := nm.settings.Call(
		"org.freedesktop.NetworkManager.Settings.AddConnection",
		0,
		hotspotDefaults,
	).Store(&connectionPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to initialize hotspot connection")
	}

	connection, err := nm.readConnectionByPath(connectionPath)
	if err != nil {
		return nil, err
	}
	return connection.makeHotspot(), nil
}

func (nm *NetworkManager) ActivateHotspot(hotspot *Hotspot) error {
	const waitTimeout = 3 * time.Second

	err := nm.manager.Call(
		"org.freedesktop.NetworkManager.ActivateConnection",
		0,
		hotspot.path,
		nm.device.Path(),
		dbus.ObjectPath("/"),
	).Err
	if err != nil {
		return errors.Wrap(err, "Failed to activate hotspot")
	}

	if err := nm.waitForDeviceState(NmDeviceStateActivated, waitTimeout); err != nil {
		return err
	}

	return nil
}

const (
	// Network connectivity is unknown. This means the connectivity checks are
	// disabled (e.g. on server installations) or has not run yet. The
	// graphical shell should assume the Internet connection might be
	// available and not present a captive portal window.
	NMConnectivityUnknown uint32 = 0

	// The host is not connected to any network. There's no active connection
	// that contains a default route to the internet and thus it makes no
	// sense to even attempt a connectivity check. The graphical shell should
	// use this state to indicate the network connection is unavailable.
	NMConnectivityNone uint32 = 1

	// The Internet connection is hijacked by a captive portal gateway. The
	// graphical shell may open a sandboxed web browser window (because the
	// captive portals typically attempt a man-in-the-middle attacks against
	// the https connections) for the purpose of authenticating to a gateway
	// and retrigger the connectivity check with CheckConnectivity() when the
	// browser window is dismissed.
	NMConnectivityPortal uint32 = 2

	// The host is connected to a network, does not appear to be able to reach
	// the full Internet, but a captive portal has not been detected.
	NMConnectivityLimited uint32 = 3

	// The host is connected to a network, and appears to be able to reach the
	// full Internet.
	NMConnectivityFull uint32 = 4
)

func (nm *NetworkManager) Connectivity() (string, error) {
	connectivity, err := nm.manager.GetProperty(
		"org.freedesktop.NetworkManager.Connectivity",
	)
	if err != nil {
		return "", errors.Wrap(err, "Failed to read connectivity status")
	}

	switch connectivity.Value().(uint32) {
	case NMConnectivityNone:
		return "none", nil
	case NMConnectivityPortal:
		return "portal", nil
	case NMConnectivityLimited:
		return "limited", nil
	case NMConnectivityFull:
		return "full", nil
	default:
		return "unknown", nil
	}
}
