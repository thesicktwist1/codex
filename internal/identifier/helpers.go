package identifier

import "fmt"

func stringToBool(private string) (bool, error) {
	switch private {
	case "1":
		return true, nil
	case "0":
		return false, nil
	default:
		return false, fmt.Errorf("invalid private parameter")
	}
}

func boolToString(private bool) string {
	if private {
		return "1"
	} else {
		return "0"
	}
}
