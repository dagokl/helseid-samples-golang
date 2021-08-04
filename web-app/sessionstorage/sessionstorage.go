package sessionstorage

import (
	"encoding/gob"

	"github.com/gorilla/sessions"
)

var Store *sessions.FilesystemStore

func Init() error {
	Store = sessions.NewFilesystemStore("", []byte("this-key-should-be-a-secret-string-not-stored-in-source-code"))
	Store.MaxLength(16384)
	gob.Register(map[string]interface{}{})
	return nil
}
