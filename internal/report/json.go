package report

import (
	"encoding/json"

	"supascope/internal/model"
)

func JSON(report model.Report) (string, error) {
	bytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes) + "\n", nil
}
