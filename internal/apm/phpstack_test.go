//go:build linux

package apm

import "testing"

func TestPHP85OffsetsMoveTheExecuteDataPointer(t *testing.T) {
	o85, ok := phpOffsetTable["8.5"]
	if !ok {
		t.Fatal("no offsets for php 8.5")
	}
	if o85.egCurrentExecuteData != 512 || o85.egCurrentExecuteData == phpOffsetTable["8.4"].egCurrentExecuteData {
		t.Fatalf("8.5 moved current_execute_data to 512, got %d", o85.egCurrentExecuteData)
	}
}

func TestClassifyWPPath(t *testing.T) {
	cases := map[string]string{
		"/var/www/wordpress/wp-content/plugins/woocommerce/includes/class-wc-query.php": "plugin:woocommerce",
		"/var/www/wordpress/wp-content/plugins/hello.php":                               "plugin:hello",
		"/var/www/wordpress/wp-content/themes/twentytwentyfour/functions.php":           "theme:twentytwentyfour",
		"/var/www/wordpress/wp-content/mu-plugins/loader.php":                           "mu-plugin:loader",
		"/var/www/wordpress/wp-includes/class-wpdb.php":                                 "wp-core",
		"/var/www/wordpress/wp-admin/admin-ajax.php":                                    "wp-core",
		"/var/www/wordpress/index.php":                                                  "wp-core",
		"/var/www/app/src/Controller.php":                                               "app",
		"":                                                                              "",
	}
	for path, want := range cases {
		if got := ClassifyWPPath(path); got != want {
			t.Errorf("ClassifyWPPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestOwnedFrame(t *testing.T) {
	if !OwnedFrame("plugin:woocommerce") || !OwnedFrame("theme:astra") || !OwnedFrame("mu-plugin:x") {
		t.Fatal("plugin/theme owners must count as owned")
	}
	if OwnedFrame("wp-core") || OwnedFrame("app") || OwnedFrame("") {
		t.Fatal("core/app must not count as owned")
	}
}
