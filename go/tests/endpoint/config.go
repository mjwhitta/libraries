package Endpoint

import "time"

// Cfg can be used to configure some default options on a per function
// basis.
var Cfg *Config = &Config{}

// Config is a simple struct that contains common arguments for
// other functions in this package.
type Config struct {
	directory string
	noEscape  bool
	timeout   time.Duration
}

// defaultCfg takes a Config with the function's default values, but
// checks if the global Cfg overrides any options.
func defaultCfg(cfg Config) Config {
	if Cfg == nil {
		Cfg = &Config{}
	}

	if Cfg.directory != "" {
		cfg.directory = Cfg.directory
	}

	if Cfg.noEscape {
		cfg.noEscape = true
	}

	if Cfg.timeout != 0 {
		cfg.timeout = Cfg.timeout
	}

	// Reset the global config after each use
	Cfg.reset()

	return cfg
}

// Directory will adjust the directory for the Config instance, then
// return itself so it can be chained inline. This is currently useful
// for Quarantine(), Read(), Unzip(), and Write(), to change the
// directory where the payload is written. The default directory is
// dependent on the function, but is typically Pwd().
func (c *Config) Directory(dir string) *Config {
	c.directory = dir
	return c
}

// NoEscape will adjust noEscape for the Config instance, then return
// itself so it can be chained inline. This is currently useful for
// Run() and Shell() to prevent argument escaping when starting a
// process on Windows. The default value is false.
func (c *Config) NoEscape() *Config {
	c.noEscape = true
	return c
}

func (c *Config) reset() *Config {
	c.directory = ""
	c.timeout = 0
	return c
}

// Timeout will adjust the timeout for the Config instance, then
// return itself so it can be chained inline. This is currently useful
// for Quarantine() and Start(). The default timeout is dependent on
// the function.
func (c *Config) Timeout(t time.Duration) *Config {
	c.timeout = t
	return c
}
