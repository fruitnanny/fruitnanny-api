package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-systemd/activation"
	"github.com/f3anaro/fruitnanny/internal/update"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
	"github.com/warthog618/gpiod"
	"github.com/warthog618/gpiod/device/rpi"
)

type settings struct {
	TemperatureOffset float32 `json:"temperatureOffset"`
	HumidityOffset    float32 `json:"humidityOffset"`
}

type server struct {
	nm           *NetworkManager
	router       *mux.Router
	sensor       *sensor
	light        *light
	updater      *update.Updater
	settings     *settings
	settingsMux  sync.Mutex
	settingsPath string
}

func Serve(addr, ifname, webroot, libexecDir, settingsPath string) {
	nm, err := NewNetworkManager(ifname)
	if err != nil {
		log.Fatal(err)
	}
	defer nm.Close()

	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)

	sensor := NewSensor()

	light, err := NewLight()
	if err != nil {
		log.Println(err)
	}
	if light != nil {
		defer light.Close()
	}

	updater, err := update.NewUpdater(libexecDir)
	if err != nil {
		log.Fatal(err)
	}

	settings, err := LoadSettings(settingsPath)
	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	server := server{
		settings:     settings,
		settingsPath: settingsPath,
		nm:           nm,
		router:       router,
		sensor:       sensor,
		light:        light,
		updater:      updater,
	}

	server.routes(webroot)

	srv := &http.Server{
		Handler: router,
		Addr:    addr,

		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	signal.Notify(quit, os.Interrupt)

	go sensor.Process()
	go gracefullShutdown(srv, sensor, quit, done)

	log.Println("Serving static files from", webroot)

	if addr == "systemd" {
		listeners, err := activation.Listeners()
		if err != nil {
			log.Panic("Cannot retrieve listeners:", err)
		}
		if len(listeners) == 0 {
			log.Fatal("Error: no systemd listener found")
		}
		err = srv.Serve(listeners[0])
	} else {
		log.Printf("Serve FruitNanny at http://%s/", addr)
		err = srv.ListenAndServe()
	}

	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	<-done
	log.Println("Server stopped")
}

func gracefullShutdown(server *http.Server, sensor *sensor, quit <-chan os.Signal, done chan<- bool) {
	<-quit
	log.Println("Server is shutting down ...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server.SetKeepAlivesEnabled(false)
	if err := server.Shutdown(ctx); err != nil {
		log.Println("Could not gracefully shutdown the server:", err)
	}

	if err := sensor.Shutdown(ctx); err != nil {
		log.Println("Failed to shutdown sensor:", err)
	}

	close(done)
}

func LoadSettings(path string) (*settings, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, errors.Wrap(err, "Could not load settings file")
	}

	var settings settings

	err = json.Unmarshal(data, &settings)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid settings")
	}
	return &settings, nil
}

func (s *server) handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := make(map[string]string)
		m["version"] = Version.String()

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(m)
	}
}

func (s *server) listConnections() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connections := s.nm.ListConnections()
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(connections)
	}
}

func (s *server) listAccessPoints() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessPoints := s.nm.ListAccessPoints()
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(accessPoints)
	}
}

func (s *server) readConnection() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connection := s.nm.ReadConnection(mux.Vars(r)["id"])
		if connection == nil {
			http.Error(w, "Not found", http.StatusGone)
		} else {
			w.Header().Add("Content-Type", "application/json")
			json.NewEncoder(w).Encode(connection)
		}
	}
}

type updateOptions struct {
	Name        string `json:"name"`
	Ssid        string `json:"ssid"`
	Autoconnect bool   `json:"autoconnect"`
	Priority    int32  `json:"priority"`
}

func (s *server) putConnection() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connection := s.nm.ReadConnection(mux.Vars(r)["id"])
		if connection == nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		dec := json.NewDecoder(r.Body)

		// There are additional fields like "type" which are ignored
		// by the update.
		// dec.DisallowUnknownFields()

		var update updateOptions
		if err := dec.Decode(&update); err != nil {
			log.Println("Bad body:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if update.Name == "" {
			http.Error(
				w,
				"Field \"name\" is required.",
				http.StatusBadRequest,
			)
			return
		}
		if update.Ssid == "" {
			http.Error(
				w,
				"Field \"ssid\" is required.",
				http.StatusBadRequest,
			)
			return
		}

		err := s.nm.UpdateConnection(
			connection,
			update.Name,
			update.Ssid,
			update.Autoconnect,
			update.Priority,
		)
		if err != nil {
			log.Println("Failed to update connection:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Println("Updated connection", connection.Name)

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(connection)
	}
}

func (s *server) deleteConnection() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connection := s.nm.ReadConnection(mux.Vars(r)["id"])
		if connection == nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		err := s.nm.DeleteConnection(connection)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

func (s *server) readActiveConnection() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connection := s.nm.ReadActiveConnection()
		if connection == nil {
			http.Error(w, "Not connected", http.StatusNotFound)
		} else {
			w.Header().Add("Content-Type", "application/json")
			json.NewEncoder(w).Encode(connection)
		}
	}
}

type activateOptions struct {
	Id   string `json:"id"`   // Connection ID
	Type string `json:"type"` // Connection type
}

func (s *server) activate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var opts activateOptions

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		if err := dec.Decode(&opts); err != nil {
			log.Println("Bad body:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if opts.Type != "wifi" && opts.Type != "hotspot" {
			log.Printf("Unknown connection type %q", opts.Type)
			http.Error(
				w,
				fmt.Sprintf(
					"Expected type \"wifi\" or \"hotspot\", got %q",
					opts.Type,
				),
				http.StatusBadRequest,
			)
			return
		}

		if opts.Type == "wifi" && opts.Id == "" {
			http.Error(w, "'id' field is required.", http.StatusBadRequest)
			return
		}

		if opts.Type == "hotspot" {
			s.activateHotspot(opts, w)
		} else {
			s.activateConnection(opts, w)
		}
	}
}

func (s *server) activateHotspot(opts activateOptions, w http.ResponseWriter) {
	hotspot, err := s.nm.ReadHotspot()
	if err != nil {
		log.Println(err)
		http.Error(w, "Failed to read hotspot", http.StatusInternalServerError)
		return
	}

	if err := s.nm.ActivateHotspot(hotspot); err != nil {
		log.Println(err)
		http.Error(
			w,
			"Failed to activate hotspot",
			http.StatusBadRequest,
		)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hotspot)
}

func (s *server) activateConnection(opts activateOptions, w http.ResponseWriter) {
	connection := s.nm.ReadConnection(opts.Id)
	if connection == nil {
		http.Error(
			w,
			fmt.Sprintf("Connection %q not found", opts.Id),
			http.StatusBadRequest,
		)
		return
	}
	if err := s.nm.ActivateConnection(connection); err != nil {
		if isAccessPointNotFound(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		} else {
			log.Println(err)
			http.Error(
				w,
				"Failed to activate connection",
				http.StatusBadRequest,
			)
		}
		return
	}

	log.Println("Activated connection", connection.Name)

	w.Header().Add("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connection)
}

type connectOptions struct {
	Ssid     string  `json:"ssid"`
	Password *string `json:"password"`
}

func (s *server) connect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var opts connectOptions

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		if err := dec.Decode(&opts); err != nil {
			log.Println("Bad body:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if opts.Ssid == "" {
			http.Error(w, "'password' field is required.", http.StatusBadRequest)
			return
		}
		connection, err := s.nm.Connect(opts.Ssid, opts.Password)
		if err != nil {
			log.Println("Failed to connect to", opts.Ssid)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Println("Connected to", connection.Name)

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(connection)
	}
}

func (s *server) disconnect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.nm.IsConnected() {
			http.Error(w, "Device is not connected", 304)
			return
		}
		if err := s.nm.Disconnect(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	}
}

func (s *server) readHotspot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hotspot, err := s.nm.ReadHotspot()
		if err != nil {
			log.Println(err)
			http.Error(
				w,
				"Hotspot cannot be read",
				http.StatusInternalServerError,
			)
		} else {
			w.Header().Add("Content-Type", "application/json")
			json.NewEncoder(w).Encode(hotspot)
		}
	}
}

type hotspotUpdateOptions struct {
	Type     string	 `json:"type"`
	Password *string `json:"password"`
	Ssid     string  `json:"ssid"`
}

func (s *server) putHotspot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hotspot, err := s.nm.ReadHotspot()
		if err != nil {
			log.Println(err)
			http.Error(
				w,
				"Hotspot cannot be read",
				http.StatusInternalServerError,
			)
			return
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var update hotspotUpdateOptions
		if err := dec.Decode(&update); err != nil {
			log.Println("Bad body:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if update.Ssid == "" {
			http.Error(
				w,
				"Field \"ssid\" is required",
				http.StatusBadRequest,
			)
			return
		}

		err = s.nm.UpdateHotspot(hotspot, update.Ssid, update.Password)
		if err != nil {
			log.Println("Failed to update hotspot:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		log.Println("Updated hotspot")

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hotspot)
	}
}

type checkpointOpts struct {
	RollbackTimeout uint `json:"rollbackTimeout"`
	Overwrite       bool `json:"overwrite"`
}

func (s *server) createCheckpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		opts := checkpointOpts{
			RollbackTimeout: 30,
			Overwrite:       false,
		}
		if r.ContentLength > 0 {
			if err := dec.Decode(&opts); err != nil {
				log.Println("Bad body:", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if opts.RollbackTimeout == 0 {
			http.Error(
				w,
				"'rollbackTimeout' field is required.",
				http.StatusBadRequest,
			)
		}
		checkpoint, err := s.nm.CreateCheckpoint(
			time.Duration(opts.RollbackTimeout)*time.Second,
			opts.Overwrite,
		)
		if err != nil {
			if isCheckpointExists(err) {
				http.Error(w, err.Error(), http.StatusConflict)
			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)

			}
		} else {
			w.Header().Add("Content-Type", "application/json")
			json.NewEncoder(w).Encode(checkpoint)
		}
	}
}

func (s *server) readCheckpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		checkpoint := s.nm.ReadCheckpoint()
		if checkpoint == nil {
			http.Error(w, "No checkpoint", http.StatusGone)
		} else {
			w.Header().Add("Content-Type", "application/json")
			json.NewEncoder(w).Encode(checkpoint)
		}
	}
}

type checkpointDeleteOpts struct {
	Mode string `json:"mode"`
}

func (s *server) deleteCheckpoint() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts := checkpointDeleteOpts{
			Mode: "destroy",
		}
		if r.ContentLength > 0 {
			dec := json.NewDecoder(r.Body)
			dec.DisallowUnknownFields()

			if err := dec.Decode(&opts); err != nil {
				log.Println("Bad body:", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		if opts.Mode == "" {
			http.Error(
				w,
				"'mode' field is required.",
				http.StatusBadRequest,
			)
		}

		if opts.Mode != "destroy" && opts.Mode != "rollback" {
			http.Error(
				w,
				fmt.Sprintf(
					"Expected mode \"destroy\" or \"rollback\", got %q",
					opts.Mode,
				),
				http.StatusBadRequest,
			)
		}

		checkpoint := s.nm.ReadCheckpoint()
		if checkpoint == nil {
			http.Error(w, "No checkpoint", http.StatusGone)
			return
		}

		if opts.Mode == "destroy" {
			s.nm.DeleteCheckpoint(checkpoint)
		} else {
			s.nm.Rollback(checkpoint)
		}
	}
}

type sensorData struct {
	Temperature float32 `json:"temperature"`
	Humidity    float32 `json:"humidity"`
}

func (s *server) readSensors() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		temperature, humidity := s.sensor.Value()

		s.settingsMux.Lock()
		data := sensorData{
			Temperature: temperature + s.settings.TemperatureOffset,
			Humidity:    humidity + s.settings.HumidityOffset,
		}
		s.settingsMux.Unlock()

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	}
}

type lightState struct {
	State bool `json:"state"`
}

func (s *server) readLight() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.light == nil {
			http.Error(
				w,
				"Light not available",
				http.StatusServiceUnavailable,
			)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		state := lightState{
			State: s.light.Value(),
		}
		json.NewEncoder(w).Encode(state)

	}
}

func (s *server) putLight() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var state lightState
		if err := dec.Decode(&state); err != nil {
			log.Println("Bad body:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if s.light == nil {
			http.Error(
				w,
				"Light not available",
				http.StatusServiceUnavailable,
			)
			return
		}

		s.light.Set(state.State)

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}
}

func (s *server) poweroff() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command("systemctl", "poweroff")
		if err := cmd.Run(); err != nil {
			log.Println("Failed to poweroff:", err)
			http.Error(
				w,
				"Failed to poweroff",
				http.StatusInternalServerError,
			)
		}
	}
}

func (s *server) reboot() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cmd := exec.Command("systemctl", "reboot")
		if err := cmd.Run(); err != nil {
			log.Println("Failed to reboot:", err)
			http.Error(
				w,
				"Failed to reboot",
				http.StatusInternalServerError,
			)
		}
	}
}

type sensor struct {
	temperature int
	humidity    int
	mux         sync.Mutex
	close       chan bool
	done        chan bool
}

func NewSensor() *sensor {
	return &sensor{
		close: make(chan bool, 1),
		done:  make(chan bool, 1),
	}
}

func (s *sensor) Process() {
	s.read()

	for {
		select {
		case <-time.After(5 * time.Second):
			s.read()
		case <-s.close:
			close(s.done)
			return
		}
	}
}

func (s *sensor) Shutdown(ctx context.Context) error {
	close(s.close)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return nil
	}
}

func (s *sensor) read() {
	s.mux.Lock()
	defer s.mux.Unlock()

	// GPIO BCM pin 24 == Physical pin 18
	temperature, err := readDHT22Device(
		"/sys/devices/platform/dht11@18/iio:device0/in_temp_input",
	)
	if err != nil {
		// if !os.IsNotExist(err) {
		//     // log.Println("DHT22 iio device not found")
		//     log.Println(err)
		// }
		// log.Println("Could not read DHT22 sensor:", err)
		return
	}
	humidity, err := readDHT22Device(
		"/sys/devices/platform/dht11@18/iio:device0/in_humidityrelative_input",
	)
	if err != nil {
		// if !os.IsNotExist(err) {
		//     // log.Println("DHT22 iio device not found")
		//     log.Println(err)
		// }
		// log.Println("Could not read DHT22 sensor:", err)
		return
	}

	s.temperature = temperature
	s.humidity = humidity
}

func (s *sensor) Value() (temperature, humidity float32) {
	s.mux.Lock()
	temperature = float32(math.Round(float64(s.temperature)/100) / 10)
	humidity = float32(math.Round(float64(s.humidity)/100) / 10)
	s.mux.Unlock()
	return
}

func readDHT22Device(path string) (int, error) {
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return 0, err
	}
	return int(value), nil
}

const (
	LightPin = rpi.GPIO17 // BCM convention

	LightDeviceName = "gpiochip0"
)

type light struct {
	chip *gpiod.Chip
	line *gpiod.Line
}

func NewLight() (*light, error) {
	chip, err := gpiod.NewChip(LightDeviceName)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open gpio device")
	}

	line, err := chip.RequestLine(LightPin, gpiod.AsOutput(0))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to open request gpio line")
	}

	return &light{
		chip: chip,
		line: line,
	}, nil
}

func (l *light) Set(state bool) {
	if state {
		l.line.SetValue(1)
	} else {
		l.line.SetValue(0)
	}
}

func (l *light) Value() bool {
	value, err := l.line.Value()
	if err != nil {
		log.Println("Failed to read light state:", err)
		return false
	}
	return value > 0
}

func (l *light) Close() {
	// Reset GPIO pin to default state
	l.line.Reconfigure(gpiod.AsInput)
	l.line.Close()

	l.chip.Close()
}

func (s *server) readSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.settingsMux.Lock()
		defer s.settingsMux.Unlock()
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.settings)
	}
}

func (s *server) putSettings() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.settingsMux.Lock()
		defer s.settingsMux.Unlock()

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()

		var settings settings
		if err := dec.Decode(&settings); err != nil {
			log.Println("Bad body:", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := writeAtomically(s.settingsPath, func(w io.Writer) error {
			return json.NewEncoder(w).Encode(settings)
		}); err != nil {
			log.Println(err)
			http.Error(w, "Failed to save settings", http.StatusInternalServerError)
			return
		}

		s.settings = &settings

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s.settings)
	}
}

func writeAtomically(dest string, write func(w io.Writer) error) (err error) {
	f, err := ioutil.TempFile(filepath.Dir(dest), "atomic-")
	if err != nil {
		return err
	}
	defer func() {
		// Clean up (best effort) in case we are returning with an error:
		if err != nil {
			// Prevent file descriptor leaks.
			f.Close()
			// Remove the tempfile to avoid filling up the file system.
			os.Remove(f.Name())
		}
	}()

	// Use a buffered writer to minimize write(2) syscalls.
	bufw := bufio.NewWriter(f)

	w := io.Writer(bufw)

	if err := write(w); err != nil {
		return err
	}

	if err := bufw.Flush(); err != nil {
		return err
	}

	// Chmod the file world-readable (ioutil.TempFile creates files with
	// mode 0600) before renaming.
	if err := f.Chmod(0644); err != nil {
		return err
	}

	// fsync(2) after fchmod(2) orders writes as per
	// https://lwn.net/Articles/270891/. Can be skipped for performance
	// for idempotent applications (which only ever atomically write new
	// files and tolerate file loss) on an ordered file systems. ext3,
	// ext4, XFS, Btrfs, ZFS are ordered by default.
	f.Sync()

	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(f.Name(), dest)
}

func (s *server) readConnectivity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectivity, err := s.nm.Connectivity()
		if err != nil {
			log.Println(err)
			http.Error(w, "Failed to read connectivity", http.StatusInternalServerError)
			return
		}
		c := make(map[string]string)
		c["connectivity"] = connectivity

		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c)
	}
}

func (s *server) readUpdates() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["download"]; ok {
			err := s.updater.Update()
			if err != nil {
				log.Println("Error:", err)
			}
		}
		updates, err := s.updater.Check()
		if err != nil {
			log.Println("Error:", err)
			http.Error(w, "Failed to read updates", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updates)
	}
}

func (s *server) putUpgrade() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		connectivity, err := s.nm.Connectivity()
		if err != nil {
			log.Println("Error:", err)
			http.Error(w, "Failed to read updates", http.StatusInternalServerError)
			return
		}

		if connectivity != "full" {
			log.Println("Cannot upgrade without full connectivity")
			http.Error(w, "Require full connectivity", http.StatusServiceUnavailable)
			return
		}

		err = s.updater.UpgradeInBackground()
		if err != nil {
			log.Println("Error:", err)
			http.Error(w, "Failed upgrade", http.StatusInternalServerError)
			return
		}
	}
}
