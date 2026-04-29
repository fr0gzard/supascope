package mask

func Secret(value string) string {
	if len(value) <= 12 {
		return "<masked>"
	}
	return value[:8] + "..." + value[len(value)-4:]
}
