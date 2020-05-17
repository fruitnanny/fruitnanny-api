package api

import "net/http"

func (s *server) routes(webroot string) {
	s.router.HandleFunc("/api/", s.handleVersion()).Methods("GET")

	s.router.HandleFunc("/api/active-connection", s.readActiveConnection()).Methods("GET")
	s.router.HandleFunc("/api/active-connection", s.activate()).Methods("PUT")
	s.router.HandleFunc("/api/active-connection", s.connect()).Methods("POST")
	s.router.HandleFunc("/api/active-connection", s.disconnect()).Methods("DELETE")

	s.router.HandleFunc("/api/connections", s.listConnections()).Methods("GET")

	s.router.HandleFunc("/api/connections/{id:[a-z0-9\\-]+}", s.readConnection()).Methods("GET")
	s.router.HandleFunc("/api/connections/{id:[a-z0-9\\-]+}", s.deleteConnection()).Methods("DELETE")
	s.router.HandleFunc("/api/connections/{id:[a-z0-9\\-]+}", s.putConnection()).Methods("PUT")

	s.router.HandleFunc("/api/hotspot", s.readHotspot()).Methods("GET")
	s.router.HandleFunc("/api/hotspot", s.putHotspot()).Methods("PUT")

	s.router.HandleFunc("/api/access-points", s.listAccessPoints()).Methods("GET")

	s.router.HandleFunc("/api/checkpoint", s.createCheckpoint()).Methods("PUT")
	s.router.HandleFunc("/api/checkpoint", s.readCheckpoint()).Methods("GET")
	s.router.HandleFunc("/api/checkpoint", s.deleteCheckpoint()).Methods("DELETE")

	s.router.HandleFunc("/api/sensors", s.readSensors()).Methods("GET")
	s.router.HandleFunc("/api/light", s.readLight()).Methods("GET")
	s.router.HandleFunc("/api/light", s.putLight()).Methods("PUT")

	s.router.HandleFunc("/api/settings", s.readSettings()).Methods("GET")
	s.router.HandleFunc("/api/settings", s.putSettings()).Methods("PUT")

	s.router.HandleFunc("/api/connectivity", s.readConnectivity()).Methods("GET")
	s.router.HandleFunc("/api/updates", s.readUpdates()).Methods("GET")
	s.router.HandleFunc("/api/upgrade", s.putUpgrade()).Methods("PUT")

	s.router.HandleFunc("/api/system/poweroff", s.poweroff()).Methods("POST")
	s.router.HandleFunc("/api/system/reboot", s.reboot()).Methods("POST")

	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir(webroot)))
}
