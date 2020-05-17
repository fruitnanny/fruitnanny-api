/*
Copyright © Lucas Kahlert

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"github.com/f3anaro/fruitnanny/internal/api"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var addr string
var ifname string
var webroot string
var settingsPath string

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Serve FruitNanny API and web UI",
	Long: `Serving FruitNanny's backend API and web UI.

The server supports systemd socket activation. Pass "systemd" as address and
the server will listen on a file descriptor provided by systemd.

The web UI is served from a webroot directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		api.Serve(addr, ifname, webroot, viper.GetString("libexec-dir"), settingsPath)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&addr, "addr", "", "0.0.0.0:8000", "address to which the API server should be bound. Use \"systemd\" for systemd socket activation.")
	serveCmd.Flags().StringVarP(&ifname, "interface", "i", "wlan0", "WiFi interface name")
	serveCmd.Flags().StringVarP(&webroot, "web-root", "", "/usr/share/fruitnanny-ui", "directory containing static files to serve")
	serveCmd.Flags().StringVarP(&settingsPath, "settings", "", "/var/lib/fruitnanny/settings.json", "path to settings file")
}
