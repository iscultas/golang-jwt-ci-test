package jwt

import "strings"

func equalMediaType(got, want string) bool {
	return strings.EqualFold(qualifyMediaType(got), qualifyMediaType(want))
}

func qualifyMediaType(mediaType string) string {
	if strings.Contains(mediaType, "/") {
		return mediaType
	}

	return "application/" + mediaType
}
