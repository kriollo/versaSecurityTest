package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/versaSecurityTest/internal/scanner"
)

// GenerateTableReport genera un reporte en formato tabla
func GenerateTableReport(result *scanner.ScanResult) string {
	var output strings.Builder

	// Header del reporte
	output.WriteString("┌─────────────────────────────────────────────────────────────────┐\n")
	output.WriteString("│                    REPORTE DE SEGURIDAD WEB                     │\n")
	output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")
	output.WriteString(fmt.Sprintf("│ URL Objetivo: %-49s │\n", truncateString(result.URL, 49)))
	output.WriteString(fmt.Sprintf("│ Fecha: %-56s │\n", result.ScanDate.Format("2006-01-02 15:04:05")))
	output.WriteString(fmt.Sprintf("│ Duración: %-53s │\n", result.Duration.Round(time.Millisecond).String()))
	output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")

	// Resumen
	output.WriteString("│                           RESUMEN                               │\n")
	output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")
	output.WriteString(fmt.Sprintf("│ Tests Ejecutados: %-44d │\n", result.TestsExecuted))
	output.WriteString(fmt.Sprintf("│ Tests Pasados: %-47d │\n", result.TestsPassed))
	output.WriteString(fmt.Sprintf("│ Tests Fallidos: %-46d │\n", result.TestsFailed))

	// Agregar información de tests saltados y timeout si existen
	if result.TestsSkipped > 0 {
		output.WriteString(fmt.Sprintf("│ Tests Saltados: %-46d │\n", result.TestsSkipped))
	}
	if result.TestsTimeout > 0 {
		output.WriteString(fmt.Sprintf("│ Tests Timeout: %-47d │\n", result.TestsTimeout))
	}

	output.WriteString(fmt.Sprintf("│ Puntuación de Seguridad: %.1f/10 (%s)%-20s │\n",
		result.SecurityScore.Value, result.SecurityScore.Risk, ""))
	output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")

	// Resultados detallados
	output.WriteString("│                      RESULTADOS DETALLADOS                     │\n")
	output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")

	for _, test := range result.TestResults {
		var status string
		switch test.Status {
		case "Passed":
			status = "✅ PASÓ"
		case "Skipped":
			status = "⏭️ SALTADO"
		case "Timeout":
			status = "⏰ TIMEOUT"
		default:
			status = "❌ FALLÓ"
		}

		output.WriteString(fmt.Sprintf("│ %s %-42s │\n", status, truncateString(test.TestName, 42)))
		output.WriteString(fmt.Sprintf("│   Severidad: %-50s │\n", test.Severity))
		output.WriteString(fmt.Sprintf("│   %s │\n", truncateAndWrap(test.Description, 63)))

		if len(test.Details) > 0 {
			output.WriteString("│   Detalles:                                                     │\n")
			for _, detail := range test.Details {
				lines := wrapText(detail, 61)
				for _, line := range lines {
					output.WriteString(fmt.Sprintf("│   - %-59s │\n", line))
				}
			}
		}
		output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")
	}

	// Recomendaciones
	if len(result.Recommendations) > 0 {
		output.WriteString("│                       RECOMENDACIONES                           │\n")
		output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")

		for i, rec := range result.Recommendations {
			lines := wrapText(fmt.Sprintf("%d. %s", i+1, rec), 63)
			for j, line := range lines {
				if j == 0 {
					output.WriteString(fmt.Sprintf("│ %-63s │\n", line))
				} else {
					output.WriteString(fmt.Sprintf("│   %-61s │\n", line))
				}
			}
		}
		output.WriteString("├─────────────────────────────────────────────────────────────────┤\n")
	}

	output.WriteString("│                     FIN DEL REPORTE                            │\n")
	output.WriteString("└─────────────────────────────────────────────────────────────────┘\n")

	return output.String()
}

// GenerateHTMLReport genera un reporte en formato HTML
func GenerateHTMLReport(result *scanner.ScanResult) string {
	var output strings.Builder

	output.WriteString(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Seguridad Web - VersaSecurityTest</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            letter-spacing: 1px;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .main-summary {
            display: flex;
            flex-wrap: wrap;
            padding: 30px;
            background: #fff;
            gap: 30px;
            border-bottom: 1px solid #eee;
        }
        .charts-container {
            flex: 1;
            min-width: 300px;
            max-width: 400px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .stats-grid {
            flex: 2;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
        }
        .stat-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #e9ecef;
            transition: transform 0.2s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .stat-card h3 {
            margin: 0 0 10px 0;
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .stat-card .value {
            font-size: 1.8em;
            font-weight: bold;
            color: #2c3e50;
        }
        .security-score-large {
            font-size: 3em !important;
            margin: 10px 0;
        }
        .risk-low { color: #2ecc71; }
        .risk-medio { color: #f1c40f; }
        .risk-alto { color: #e67e22; }
        .risk-crítico { color: #e74c3c; }
        
        .tests-section {
            padding: 30px;
        }
        .test-result {
            margin-bottom: 15px;
            border: 1px solid #eee;
            border-radius: 8px;
            overflow: hidden;
        }
        .test-header {
            padding: 12px 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        .test-passed { background: #e8f5e9; color: #2e7d32; border-left: 5px solid #2ecc71; }
        .test-failed { background: #ffebee; color: #c62828; border-left: 5px solid #e74c3c; }
        .test-skipped { background: #eceff1; color: #455a64; border-left: 5px solid #90a4ae; }
        
        .severity {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 0.75em;
            text-transform: uppercase;
        }
        .severity-high { background: #e74c3c; color: white; }
        .severity-medium { background: #f1c40f; color: black; }
        .severity-low { background: #2ecc71; color: white; }
        .severity-none { background: #95a5a6; color: white; }
        
        .test-body {
            padding: 20px;
            background: white;
            border-top: 1px solid #eee;
        }
        .recommendations {
            background: #f0f7ff;
            padding: 40px 30px;
            border-top: 1px solid #e3f2fd;
        }
        .recommendations h2 {
            color: #1976d2;
            margin-top: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .recommendation-list {
            list-style: none;
            padding: 0;
        }
        .recommendation-item {
            background: white;
            padding: 15px 20px;
            margin-bottom: 10px;
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.02);
            display: flex;
            align-items: flex-start;
            gap: 15px;
        }
        .recommendation-item::before {
            content: "💡";
            font-size: 1.2em;
        }
        footer {
            text-align: center;
            padding: 20px;
            color: #95a5a6;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VersaSecurityTest</h1>
            <p>Reporte de Auditoría de Seguridad Web</p>
        </div>

        <div class="main-summary">
            <div class="charts-container">
                <canvas id="resultsChart"></canvas>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Puntuación de Seguridad</h3>
                    <div class="value security-score-large risk-`)

	output.WriteString(strings.ToLower(result.SecurityScore.Risk))
	output.WriteString(`">`)
	output.WriteString(fmt.Sprintf("%.1f / 10", result.SecurityScore.Value))
	output.WriteString(`</div>
                    <div style="font-weight: bold; color: #666;">Nivel: `)
	output.WriteString(result.SecurityScore.Risk)
	output.WriteString(`</div>
                </div>
                <div class="stat-card">
                    <h3>URL Objetivo</h3>
                    <div class="value" style="font-size: 1.1em; word-break: break-all;">`)
	output.WriteString(html.EscapeString(result.URL))
	output.WriteString(`</div>
                </div>
                <div class="stat-card">
                    <h3>Tests Ejecutados</h3>
                    <div class="value">`)
	output.WriteString(fmt.Sprintf("%d", result.TestsExecuted))
	output.WriteString(`</div>
                    <div style="font-size: 0.85em; color: #999;">`)
	output.WriteString(fmt.Sprintf("Pasados: %d | Fallidos: %d", result.TestsPassed, result.TestsFailed))
	output.WriteString(`</div>
                </div>
                <div class="stat-card">
                    <h3>Fecha y Tiempo</h3>
                    <div class="value" style="font-size: 1.1em;">`)
	output.WriteString(result.ScanDate.Format("2006-01-02 15:04"))
	output.WriteString(`</div>
                    <div style="font-size: 0.85em; color: #999;">Duración: `)
	output.WriteString(result.Duration.Round(time.Millisecond).String())
	output.WriteString(`</div>
                </div>
            </div>
        </div>

        <div class="tests-section">
            <h2>🔍 Detalles del Análisis</h2>`)

	for _, test := range result.TestResults {
		statusClass := "test-passed"
		statusIcon := "✅"
		if test.Status == "Failed" {
			statusClass = "test-failed"
			statusIcon = "❌"
		} else if test.Status == "Skipped" || test.Status == "Timeout" {
			statusClass = "test-skipped"
			statusIcon = "⚠️"
		}

		severityClass := "severity-" + strings.ToLower(test.Severity)
		if test.Severity == "None" {
			severityClass = "severity-none"
		}

		output.WriteString(fmt.Sprintf(`
            <div class="test-result">
                <div class="test-header %s">
                    <span>%s %s</span>
                    <span class="severity %s">%s</span>
                </div>
                <div class="test-body">
                    <p><strong>Descripción:</strong> %s</p>`,
			statusClass, statusIcon, html.EscapeString(test.TestName), severityClass, test.Severity, html.EscapeString(test.Description)))

		if len(test.Details) > 0 {
			output.WriteString(`
                    <div class="details">
                        <strong>Hallazgos y Detalles:</strong>
                        <ul>`)
			for _, detail := range test.Details {
				output.WriteString(fmt.Sprintf("<li>%s</li>", html.EscapeString(detail)))
			}
			output.WriteString(`
                        </ul>
                    </div>`)
		}

		output.WriteString(`
                </div>
            </div>`)
	}

	output.WriteString(`
        </div>`)

	// Recomendaciones
	if len(result.Recommendations) > 0 {
		output.WriteString(`
        <div class="recommendations">
            <h2>🎯 Recomendaciones de Seguridad</h2>
            <div class="recommendation-list">`)

		for _, rec := range result.Recommendations {
			output.WriteString(fmt.Sprintf(`
                <div class="recommendation-item">
                    <span>%s</span>
                </div>`, html.EscapeString(rec)))
		}

		output.WriteString(`
            </div>
        </div>`)
	}

	output.WriteString(`
        <footer>
            Generado automáticamente por VersaSecurityTest v1.3.0 &copy; ` + time.Now().Format("2006") + `
        </footer>
    </div>

    <script>
        const ctx = document.getElementById('resultsChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Pasados', 'Fallidos', 'Otros'],
                datasets: [{
                    data: [`)
	output.WriteString(fmt.Sprintf("%d, %d, %d", result.TestsPassed, result.TestsFailed, result.TestsSkipped+result.TestsTimeout))
	output.WriteString(`],
                    backgroundColor: ['#2ecc71', '#e74c3c', '#95a5a6'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom',
                    }
                },
                cutout: '70%'
            }
        });
    </script>
</body>
</html>`)

	return output.String()
}

// Funciones auxiliares

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func truncateAndWrap(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func wrapText(text string, width int) []string {
	var lines []string
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}

	currentLine := words[0]
	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= width {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)

	return lines
}

// ReportOptions contiene las opciones para generar y guardar reportes
type ReportOptions struct {
	Format        string // "json", "html", "table"
	OutputFile    string // ruta específica del archivo, si está vacía se genera automáticamente
	AutoSave      bool   // si se debe auto-guardar
	UseReportsDir bool   // si se debe usar el directorio reports/
}

// GenerateReport genera un reporte en el formato especificado
func GenerateReport(result *scanner.ScanResult, format string) (string, error) {
	switch format {
	case "json":
		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return "", fmt.Errorf("error generando reporte JSON: %w", err)
		}
		return string(jsonBytes), nil

	case "html":
		return GenerateHTMLReport(result), nil

	case "table":
		return GenerateTableReport(result), nil

	default:
		return "", fmt.Errorf("formato no soportado: %s", format)
	}
}

// GenerateReportFilename genera un nombre de archivo automático basado en la URL y formato
func GenerateReportFilename(targetURL, format string, useReportsDir bool) string {
	// Limpiar la URL para usar como nombre de archivo
	cleanURL := cleanURLForFilename(targetURL)

	// Timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")

	// Extensión según formato
	var ext string
	switch format {
	case "html":
		ext = ".html"
	case "table":
		ext = ".txt"
	default:
		ext = ".json"
	}

	// Construir nombre del archivo
	filename := fmt.Sprintf("scan_%s_%s%s", cleanURL, timestamp, ext)

	// Si se debe usar directorio reports/, crearlo y agregar al path
	if useReportsDir {
		reportsDir := "reports"
		os.MkdirAll(reportsDir, 0755)
		filename = filepath.Join(reportsDir, filename)
	}

	return filename
}

// SaveReport guarda un reporte con las opciones especificadas
func SaveReport(result *scanner.ScanResult, options ReportOptions) (string, error) {
	// Generar contenido del reporte
	content, err := GenerateReport(result, options.Format)
	if err != nil {
		return "", err
	}

	// Determinar nombre del archivo
	var filename string
	if options.OutputFile != "" {
		filename = options.OutputFile
		// Si se especifica UseReportsDir y el archivo no tiene ruta, agregarlo al directorio reports/
		if options.UseReportsDir && !strings.Contains(filename, string(filepath.Separator)) {
			reportsDir := "reports"
			os.MkdirAll(reportsDir, 0755)
			filename = filepath.Join(reportsDir, filename)
		}
	} else {
		// Generar nombre automático
		filename = GenerateReportFilename(result.URL, options.Format, options.UseReportsDir)
	}

	// Guardar archivo
	err = os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		return "", fmt.Errorf("error guardando archivo %s: %w", filename, err)
	}

	return filename, nil
}

// AutoSaveReport guarda automáticamente el reporte en formato JSON en el directorio reports/
func AutoSaveReport(result *scanner.ScanResult) (string, error) {
	options := ReportOptions{
		Format:        "json",
		AutoSave:      true,
		UseReportsDir: true,
	}
	return SaveReport(result, options)
}

// cleanURLForFilename limpia una URL para usarla como nombre de archivo
func cleanURLForFilename(url string) string {
	cleanURL := strings.ReplaceAll(url, "://", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "/", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "?", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "&", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "=", "_")
	cleanURL = strings.ReplaceAll(cleanURL, ":", "_")
	cleanURL = strings.ReplaceAll(cleanURL, " ", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "%", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "#", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "@", "_")

	// Remover caracteres especiales adicionales
	cleanURL = strings.ReplaceAll(cleanURL, "[", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "]", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "{", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "}", "_")
	cleanURL = strings.ReplaceAll(cleanURL, "(", "_")
	cleanURL = strings.ReplaceAll(cleanURL, ")", "_")

	// Limitar longitud del nombre
	if len(cleanURL) > 50 {
		cleanURL = cleanURL[:50]
	}

	return cleanURL
}
