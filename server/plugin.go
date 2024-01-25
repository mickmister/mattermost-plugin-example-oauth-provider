package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
)

type Plugin struct {
	plugin.MattermostPlugin

	configurationLock sync.RWMutex

	configuration *configuration
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/token":
		p.handleTokenRequest(w, r)
	case "/command":
		p.handleCommandRequest(w, r)
	case "/webhook":
		p.handleWebhookRequest(w, r)
	default:
		handleNotFound(w, r)
	}
}

func (p *Plugin) handleWebhookRequest(w http.ResponseWriter, r *http.Request) {
	webhookResponse := model.OutgoingWebhookResponse{
		Text: model.NewString("called the webhook"),
	}

	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(webhookResponse)
	if err != nil {
		p.API.LogError("failed to marshal webhook response", "err", err.Error())
	}
}

func (p *Plugin) handleCommandRequest(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	tokenType, accessToken := parts[0], parts[1]

	msg := fmt.Sprintf("token type: '%s' access token: '%s'", tokenType, accessToken)

	// TODO make a plugin setting and verify token matches here

	commandResponse := model.CommandResponse{
		Text:         msg,
		ResponseType: model.CommandResponseTypeEphemeral,
	}

	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(commandResponse)
	if err != nil {
		p.API.LogError("failed to marshal command response", "err", err.Error())
	}
}

func (p *Plugin) handleTokenRequest(w http.ResponseWriter, r *http.Request) {
	conf := p.getConfiguration()

	tokenResponse := TokenResponse{
		AccessToken: conf.AccessToken,
		TokenType:   "Bearer",
	}

	w.Header().Add("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(tokenResponse)
	if err != nil {
		p.API.LogError("failed to marshal token response", "err", err.Error())
	}
}

func handleNotFound(w http.ResponseWriter, r *http.Request) {
	msg := fmt.Sprintf("OAuth Example plugin does not handle the path `%s`", r.URL.Path)
	http.Error(w, msg, http.StatusNotFound)
}

// See https://developers.mattermost.com/extend/plugins/server/reference/
