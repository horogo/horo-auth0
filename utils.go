package hrauth0

func assert1(guard bool, msg string) {
	if !guard {
		panic(msg)
	}
}