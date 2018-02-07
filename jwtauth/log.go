package jwtauth

// Logger interface compatible with NATS Server
type Logger interface {
	// Log an error
	Errorf(format string, v ...interface{})

	// Log a debug statement
	Debugf(format string, v ...interface{})
}

// SetLogger set logger
func (auth *JWTAuth) SetLogger(logger Logger) {
	auth.logger = logger
}

// Errorf for error logs
func (auth *JWTAuth) Errorf(format string, v ...interface{}) {
	if auth.logger != nil {
		auth.logger.Errorf(format, v...)
	}
}

// Debugf for debug log
func (auth *JWTAuth) Debugf(format string, v ...interface{}) {
	if auth.logger != nil {
		auth.logger.Debugf(format, v...)
	}
}
