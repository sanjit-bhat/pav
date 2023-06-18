package promptui

import (
	"errors"
	"fmt"
)

type Select struct {
	Label string
	Items []string
}

func (sel *Select) Run() (string, error) {
	if _, err := fmt.Print(sel.Label, sel.Items, ": "); err != nil {
		return "", err
	}
	var out string
	if _, err := fmt.Scanln(&out); err != nil {
		return "", err
	}
	for _, item := range sel.Items {
		if out == item {
			return out, nil
		}
	}
	return "", errors.New("received user input outside set of allowed selections")
}

type Prompt struct {
	Label string
}

func (prompt *Prompt) Run() (string, error) {
	if _, err := fmt.Print(prompt.Label, ": "); err != nil {
		return "", err
	}
	var out string
	if _, err := fmt.Scanln(&out); err != nil {
		return "", err
	}
	return out, nil
}
