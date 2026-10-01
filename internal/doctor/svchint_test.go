package doctor

import "testing"

func TestServiceCmdPerPlatform(t *testing.T) {
	defer func(g string, e func(string) bool) { hintGOOS, hintExists = g, e }(hintGOOS, hintExists)
	cases := []struct {
		goos, present, want string
	}{
		{"linux", "/run/systemd/system", "systemctl restart wakora-agent"},
		{"linux", "/run/openrc", "rc-service wakora-agent restart"},
		{"linux", "", "/etc/init.d/wakora-agent restart"},
		{"windows", "", "wakora service restart"},
		{"darwin", "", "wakora service restart"},
	}
	for _, c := range cases {
		hintGOOS = c.goos
		present := c.present
		hintExists = func(p string) bool { return p == present }
		if got := serviceCmd("restart"); got != c.want {
			t.Fatalf("%s %q: got %q want %q", c.goos, c.present, got, c.want)
		}
	}
}
