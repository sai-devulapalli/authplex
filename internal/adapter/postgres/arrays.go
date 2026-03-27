package postgres

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// pgArray wraps a string slice for PostgreSQL TEXT[] compatibility via database/sql.
type pgArray []string

// Value implements driver.Valuer for INSERT/UPDATE.
func (a pgArray) Value() (driver.Value, error) {
	if a == nil {
		return "{}", nil
	}
	escaped := make([]string, len(a))
	for i, s := range a {
		escaped[i] = fmt.Sprintf(`"%s"`, strings.ReplaceAll(s, `"`, `\"`))
	}
	return "{" + strings.Join(escaped, ",") + "}", nil
}

// Scan implements sql.Scanner for SELECT.
func (a *pgArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("pgArray: unsupported type %T", src)
	}

	// Parse PostgreSQL array format: {val1,val2,...}
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		*a = []string{}
		return nil
	}

	*a = parsePostgresArray(s)
	return nil
}

func parsePostgresArray(s string) []string {
	var result []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for _, ch := range s {
		if escaped {
			current.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if ch == ',' && !inQuote {
			result = append(result, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(ch)
	}
	if current.Len() > 0 {
		result = append(result, current.String())
	}
	return result
}
