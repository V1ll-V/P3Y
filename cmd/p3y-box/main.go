package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"p3y/ctfrunner"
)

func main() {
	token := os.Getenv("P3Y_BOX_TOKEN")
	if len(token) < 24 {
		log.Fatal("P3Y_BOX_TOKEN must contain at least 24 characters")
	}
	image := os.Getenv("P3Y_BOX_TOOL_IMAGE")
	if image == "" {
		image = "p3y/p3y-box-tools:20261109"
	}
	s := &ctfrunner.Server{Engine: ctfrunner.DockerEngine("/var/run/docker.sock", image), Token: token, StateDir: "/state"}
	go func() {
		for range time.Tick(time.Minute) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			s.Collect(ctx, time.Now().Add(-time.Hour))
			cancel()
		}
	}()
	log.Fatal((&http.Server{Addr: ":8790", Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}
