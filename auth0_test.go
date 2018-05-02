package hrauth0

import (
	"testing"
	"net/http/httptest"
)

func TestAuth0_Handler(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlEwRXdNVVE1TjBVMlFUa3pNamRFTjBOQ09EQTVRVUpHUmtORE0wVXlNRGxHTmpKQlFUVXdPQSJ9.eyJpc3MiOiJodHRwczovL2hvbG8uYXUuYXV0aDAuY29tLyIsInN1YiI6Imdvb2dsZS1vYXV0aDJ8MTE3MjkwMDMzNzEzNjg1MjIxOTc4IiwiYXVkIjpbImh0dHA6Ly9hdXRoLmhvcm8ubWUiLCJodHRwczovL2hvbG8uYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImlhdCI6MTUyNTI2NDQ5MiwiZXhwIjoxNTI1MjcxNjkyLCJhenAiOiJlUVZ0Y2dLS3R4NWk0VjhOUXpQM0JhZlNrNFBKemhGUCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgbWFuYWdlOnRhZyBtYW5hZ2U6cG9zdCByZWFkOnRhZyByZWFkOnBvc3QifQ.gPA7QvfNScjgCE1zpG4D7wPFbs7KylPoDvr9t9OO2QNUVgyZS9mCNu0dCSwD1VMyr3PD08n9yx8Q8J8aLS5cdzERFhZILLx0IXZd7zmcMk8KRVXPyWbiyZkDzA1EcHZSGxttQWKOy2aqeb8XN58zs84EZhOzu4r0sFXiVsk-L-XnqBoJElKfkr80BAG66n8zd70qvmiOGGlJMwVFZ-eKuNjglHdG5r73UlMCY6zrPWF0WkyUJZIqeNtcyJe6hq-CqSPpzd0xVhnBX0RvuSP1hlQC6_dntFwoNL_-HK93d9hpvc0uVshJF9SS30LWq9V3L_N9LWn2thmliOC4KE7ylA")

	au := New(
		[]string{"http://auth.horo.me"},
		"https://holo.au.auth0.com/",
		"https://holo.au.auth0.com/.well-known/jwks.json")

	handler := au.Handler()(nil)

	handler.ServeHTTP(nil, r)
}
