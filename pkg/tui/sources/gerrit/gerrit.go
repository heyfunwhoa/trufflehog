package gerrit

import (
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/tui/components/textinputs"
)

type gerritCmdModel struct {
	textinputs.Model
}

func GetNote() string {
	return "If no username and password are provided, TruffleHog will attempt an unauthenticated Gerrit scan. Use an HTTP password from Gerrit Settings → HTTP Credentials, not your account password."
}

func GetFields() gerritCmdModel {
	return gerritCmdModel{textinputs.New([]textinputs.InputConfig{
		{
			Label:       "Endpoint URL",
			Key:         "endpoint",
			Required:    true,
			Help:        "URL of the Gerrit server.",
			Placeholder: "https://gerrit.example.com",
		},
		{
			Label:    "Username",
			Key:      "username",
			Required: false,
			Help:     "For authenticated scans - pairs with HTTP password.",
		},
		{
			Label:    "Password",
			Key:      "password",
			Required: false,
			Help:     "Gerrit HTTP password from Settings → HTTP Credentials.",
		},
		{
			Label:       "Project",
			Key:         "project",
			Required:    false,
			Help:        "Gerrit project to scan. Leave empty to enumerate all accessible projects.",
			Placeholder: "my/project",
		},
	})}
}

func checkIsAuthenticated(inputs map[string]textinputs.Input) bool {
	return inputs["username"].Value != "" && inputs["password"].Value != ""
}

func (m gerritCmdModel) Cmd() string {
	var command []string
	command = append(command, "trufflehog", "gerrit")
	inputs := m.GetInputs()

	keys := []string{"endpoint"}
	if checkIsAuthenticated(inputs) {
		keys = append(keys, "username", "password")
	}
	if inputs["project"].Value != "" {
		keys = append(keys, "project")
	}

	for _, key := range keys {
		val, ok := inputs[key]
		if !ok || val.Value == "" {
			continue
		}
		command = append(command, "--"+key+"="+val.Value)
	}

	return strings.Join(command, " ")
}

func (m gerritCmdModel) Summary() string {
	inputs := m.GetInputs()
	labels := m.GetLabels()

	summaryKeys := []string{"endpoint"}
	if checkIsAuthenticated(inputs) {
		summaryKeys = append(summaryKeys, "username", "password")
	}
	if inputs["project"].Value != "" {
		summaryKeys = append(summaryKeys, "project")
	}

	return common.SummarizeSource(summaryKeys, inputs, labels)
}
