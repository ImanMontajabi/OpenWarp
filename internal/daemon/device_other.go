//go:build !darwin

package daemon

func hardwareModel() string { return "" }
