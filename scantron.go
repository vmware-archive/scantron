package scantron

type Host struct {
	Name      string   `yaml:"name"`
	Username  string   `yaml:"username"`
	Password  string   `yaml:"password"`
	Addresses []string `yaml:"addresses"`
}

type Inventory struct {
	Hosts []Host `yaml:"hosts"`
}
