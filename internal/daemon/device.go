package daemon

import "runtime"

// Identity used by releases before platform detection; kept as a fallback.
const (
	legacyDeviceType  = "Android"
	legacyDeviceModel = "PC"
)

// deviceIdentity returns the device type and model sent at registration,
// matching the official clients (macOS sends "macOS" and hw.model, e.g. "Mac16,8").
func deviceIdentity() (deviceType, model string) {
	switch runtime.GOOS {
	case "darwin":
		deviceType = "macOS"
	case "windows":
		deviceType = "Windows"
	case "linux":
		deviceType = "Linux"
	default:
		return legacyDeviceType, legacyDeviceModel
	}
	model = hardwareModel()
	if model == "" {
		model = "PC"
	}
	return deviceType, model
}
