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
	conf := p.getConfiguration()

	authHeader := r.Header.Get("Authorization")
	parts := strings.Split(authHeader, " ")
	tokenType, accessToken := parts[0], parts[1]

	w.Header().Add("Content-Type", "application/json")

	if tokenType != "Bearer" {
		responseBody := map[string]string{"error": "Invalid value for token type. Expected 'Bearer'. Got " + tokenType + " " + accessToken}
		b, _ := json.Marshal(responseBody)
		http.Error(w, string(b), http.StatusBadRequest)
		return
	}

	if accessToken != conf.AccessToken {
		http.Error(w, `{"error": "Invalid access token provided"}`, http.StatusBadRequest)
		return
	}

	msg := fmt.Sprintf("token type: '%s' access token: '%s'", tokenType, accessToken)

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

	w.Header().Add("Content-Type", "application/json")

	r.ParseForm()

	clientId := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	grantType := r.Form.Get("grant_type")

	if clientId != conf.ExpectedClientId {
		http.Error(w, `{"error": "Invalid value for client id"}`, http.StatusBadRequest)
		return
	}

	if clientSecret != conf.ExpectedClientSecret {
		http.Error(w, `{"error": "Invalid value for client secret"}`, http.StatusBadRequest)
		return
	}

	if grantType != "client_credentials" {
		http.Error(w, `{"error": "Invalid value for grant_type. Should be client_credentials."}`, http.StatusBadRequest)
		return
	}

	tokenResponse := TokenResponse{
		AccessToken: conf.AccessToken,
		TokenType:   "Bearer",
	}

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
