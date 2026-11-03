package tests

import "strings"

// sqlErrorSignatures son fragmentos que solo aparecen en un mensaje de error real de base de datos.
// Se usan para confirmar una inyección SQL por error, en vez de adivinar por el status o por la palabra "sql".
var sqlErrorSignatures = []string{
	// MySQL / MariaDB
	"you have an error in your sql syntax",
	"warning: mysql_",
	"valid mysql result",
	"check the manual that corresponds to your mariadb server version",
	"mysqli_sql_exception",
	// MSSQL
	"microsoft ole db provider for sql server",
	"unclosed quotation mark after the character string",
	"incorrect syntax near",
	"sql server error",
	// SQLite
	"sqlite3::query",
	"sqlite_error",
	"sqlsyntaxerror: near",
	"unrecognized token:",
	// PostgreSQL
	"invalid input syntax for type",
	"unterminated quoted string",
	"postgresql query failed",
	"pg_query():",
	// Oracle
	"ora-0",
	"quoted string not properly terminated",
	// Genéricos pero específicos de error de BD (no la mera palabra "sql")
	"sql syntax",
	"syntax error at or near",
}

// matchSQLError devuelve la primera firma de error de base de datos encontrada en el cuerpo, si la hay.
func matchSQLError(body string) (string, bool) {
	lower := strings.ToLower(body)
	for _, sig := range sqlErrorSignatures {
		if strings.Contains(lower, sig) {
			return sig, true
		}
	}
	return "", false
}
