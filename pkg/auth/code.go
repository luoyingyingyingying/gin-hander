package auth

type StatusCode int

const (
	moduleErrorCodePrefix            = 0x10000
	StatusCodeBadToken    StatusCode = iota + moduleErrorCodePrefix
	StatusCodeTokenTimeout
	StatusCodeTokenRequired
	StatusCodeDeviceRequired
	StatusCodeBadDevice
	StatusCodeDeviceNotFound
	StatusCodeTokenExpired
)

func (s StatusCode) Code() int {
	return int(s)
}

func (s StatusCode) Error() string {
	switch s {
	case StatusCodeBadToken:
		return "bad token"
	case StatusCodeTokenTimeout:
		return "token timeout"
	case StatusCodeTokenRequired:
		return "token required"
	case StatusCodeDeviceRequired:
		return "device required"
	case StatusCodeBadDevice:
		return "bad device"
	case StatusCodeDeviceNotFound:
		return "device not found"
	case StatusCodeTokenExpired:
		return "token expired"
	default:
		return "unknown"
	}
}
