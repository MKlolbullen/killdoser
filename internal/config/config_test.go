package config

import (
	"strings"
	"testing"
)

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := ParseFlags([]string{"--target", "10.0.0.1", "--port", "80"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "10.0.0.1" || cfg.Port != 80 {
		t.Fatalf("unexpected: %+v", cfg)
	}
	if cfg.Mode != ModeTCP {
		t.Fatalf("default mode wrong: %q", cfg.Mode)
	}
	if cfg.Interactive {
		t.Fatal("should not force interactive when flags are present")
	}
}

func TestParseFlagsInteractiveWhenEmpty(t *testing.T) {
	cfg, err := ParseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Interactive {
		t.Fatal("empty argv should trigger interactive mode")
	}
}

func TestParseFlagsRejectsBadMode(t *testing.T) {
	_, err := ParseFlags([]string{"--mode", "bogus", "--target", "x"})
	if err == nil {
		t.Fatal("bogus mode should error")
	}
}

func TestValidate(t *testing.T) {
	c := Defaults()
	c.Target = "10.0.0.1"
	if err := c.Validate(); err != nil {
		t.Fatalf("should validate: %v", err)
	}
	c.Mode = "nope"
	if err := c.Validate(); err == nil {
		t.Fatal("invalid mode should fail validation")
	}
	c.Mode = ModeTCP
	c.Duration = 0
	c.Count = 0
	if err := c.Validate(); err == nil {
		t.Fatal("missing termination should fail validation")
	}
}

func TestApplyEncoding(t *testing.T) {
	cases := []struct {
		enc  Encoding
		in   string
		want string
	}{
		{EncodeURL, "a b", "a+b"},
		{EncodeHTML, "<a>", "&lt;a&gt;"},
		{EncodeBase64, "hi", "aGk="},
		{EncodeUnicode, "hi", `\u0068\u0069`},
		{EncodeNone, "hi", "hi"},
	}
	for _, c := range cases {
		cfg := Defaults()
		cfg.Payload = c.in
		cfg.Encoding = c.enc
		if err := cfg.ApplyEncoding(); err != nil {
			t.Fatalf("%s: %v", c.enc, err)
		}
		if cfg.Payload != c.want {
			t.Errorf("%s: got %q want %q", c.enc, cfg.Payload, c.want)
		}
	}
}

func TestWizardRequiresAuthorization(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		"1", "10.0.0.1", "80", "", "none", "", "", "", "n", "",
	}, "\n") + "\n")
	_, err := Wizard(in, &strings.Builder{})
	if err == nil {
		t.Fatal("wizard should refuse without authorization")
	}
}
