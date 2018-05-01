package hrauth0

import "log"

func (au Auth0) debugf(format string, values ...interface{}) {
	if au.debug {
		log.Printf("[HORO-AUTH0][DEBUG] "+format, values...)
	}
}

func (au Auth0) errorf(format string, err error) {
	if au.debug {
		log.Printf("[HORO-AUTH0][DEBUG] "+format, err)
	}
}
