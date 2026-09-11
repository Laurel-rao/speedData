package main

import (
	"io"
	"sync"
	"time"
)

type preparationState struct {
	ID          string  `json:"id"`
	Stage       string  `json:"stage"`
	Active      bool    `json:"active"`
	Compressed  bool    `json:"compressed"`
	Remote      string  `json:"remote"`
	Current     string  `json:"current"`
	TotalFiles  int     `json:"total_files"`
	DoneFiles   int     `json:"done_files"`
	TotalBytes  int64   `json:"total_bytes"`
	DoneBytes   int64   `json:"done_bytes"`
	ZipBytes    int64   `json:"zip_bytes"`
	VerifyBytes int64   `json:"verify_bytes"`
	Elapsed     float64 `json:"elapsed"`
	Error       string  `json:"error,omitempty"`
}

type preparation struct {
	mu      sync.Mutex
	state   preparationState
	started time.Time
}

func (progress *preparation) update(change func(*preparationState)) {
	if progress == nil {
		return
	}
	progress.mu.Lock()
	defer progress.mu.Unlock()
	change(&progress.state)
}

func (progress *preparation) snapshot() preparationState {
	if progress == nil {
		return preparationState{Stage: "idle"}
	}
	progress.mu.Lock()
	defer progress.mu.Unlock()
	state := progress.state
	if state.Active {
		state.Elapsed = time.Since(progress.started).Seconds()
	}
	return state
}

func (progress *preparation) finish(message string) {
	progress.update(func(state *preparationState) {
		state.Active = false
		state.Elapsed = time.Since(progress.started).Seconds()
		state.Error = message
		state.Stage = "ready"
		if message != "" {
			state.Stage = "error"
		}
	})
}

func (app *App) startPreparation(remote string, compressed bool) (*preparation, bool) {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.preparing.snapshot().Active {
		return nil, false
	}
	progress := &preparation{started: time.Now(), state: preparationState{
		ID: newToken(), Stage: "scanning", Active: true, Remote: remote, Compressed: compressed,
	}}
	app.preparing = progress
	return progress, true
}

func (app *App) preparationState() preparationState {
	app.mu.Lock()
	progress := app.preparing
	app.mu.Unlock()
	return progress.snapshot()
}

type progressWriter struct {
	writer  io.Writer
	advance func(int64)
}

func (writer *progressWriter) Write(data []byte) (int, error) {
	count, err := writer.writer.Write(data)
	if count > 0 {
		writer.advance(int64(count))
	}
	return count, err
}
