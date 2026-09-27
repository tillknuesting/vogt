package policy

import _ "embed"

// Example is a starting policy covering every provider Vogt supports.
//
//go:embed example.json
var Example []byte
