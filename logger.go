package rcon

// Logger is a simple interface that defines a logger
// used on the implementation, you can create your custom logger
// and set the Logger for the RCON struct
type Logger interface {
	Printf(format string, v ...interface{})
}
