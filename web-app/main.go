package main

import (
	"helseid-webapp/auth"
	"helseid-webapp/server"
	"helseid-webapp/sessionstorage"
)

func main() {
	sessionstorage.Init()
	auth.RefreshHelseidMetadata()
	server.StartServer()
}
