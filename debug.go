package auth0

import "log"

func (au Auth0) debugPrint(format string, values ...interface{}) {
	if au.debug {
		log.Printf("[HORO-AUTH0] "+format, values...)
	}
}
