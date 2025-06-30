package report

import (
	"fmt"
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
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #333;
        }
        .summary-card .value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .security-score {
            font-size: 3em !important;
        }
        .risk-low { color: #28a745; }
        .risk-medio { color: #ffc107; }
        .risk-alto { color: #fd7e14; }
        .risk-crítico { color: #dc3545; }
        .tests-section {
            padding: 30px;
        }
        .test-result {
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
        }
        .test-header {
            padding: 15px 20px;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .test-passed { background: #d4edda; color: #155724; }
        .test-failed { background: #f8d7da; color: #721c24; }
        .test-body {
            padding: 20px;
            background: white;
        }
        .severity {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .severity-high { background: #dc3545; color: white; }
        .severity-medium { background: #ffc107; color: black; }
        .severity-low { background: #28a745; color: white; }
        .severity-none { background: #6c757d; color: white; }
        .details {
            margin-top: 15px;
        }
        .details ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .recommendations {
            background: #e3f2fd;
            padding: 30px;
            margin-top: 20px;
        }
        .recommendations h2 {
            color: #1565c0;
            margin-top: 0;
        }
        .recommendations ol {
            padding-left: 20px;
        }
        .recommendations li {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Reporte de Seguridad Web</h1>
            <p>Generado por VersaSecurityTest</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>URL Objetivo</h3>
                <div class="value" style="font-size: 1.2em;">`)
	
	output.WriteString(result.URL)
	output.WriteString(`</div>
            </div>
            <div class="summary-card">
                <h3>Fecha de Escaneo</h3>
                <div class="value" style="font-size: 1.2em;">`)
	
	output.WriteString(result.ScanDate.Format("2006-01-02 15:04"))
	output.WriteString(`</div>
            </div>
            <div class="summary-card">
                <h3>Duración</h3>
                <div class="value">`)
	
	output.WriteString(result.Duration.Round(time.Millisecond).String())
	output.WriteString(`</div>
            </div>
            <div class="summary-card">
                <h3>Tests Ejecutados</h3>
                <div class="value">`)
	
	output.WriteString(fmt.Sprintf("%d", result.TestsExecuted))
	output.WriteString(`</div>
            </div>
            <div class="summary-card">
                <h3>Tests Pasados</h3>
                <div class="value" style="color: #28a745;">`)
	
	output.WriteString(fmt.Sprintf("%d", result.TestsPassed))
	output.WriteString(`</div>
            </div>
            <div class="summary-card">
                <h3>Tests Fallidos</h3>
                <div class="value" style="color: #dc3545;">`)
	
	output.WriteString(fmt.Sprintf("%d", result.TestsFailed))
	output.WriteString(`</div>
            </div>
            <div class="summary-card">
                <h3>Puntuación de Seguridad</h3>
                <div class="value security-score risk-`)
	
	output.WriteString(strings.ToLower(result.SecurityScore.Risk))
	output.WriteString(`">`)
	output.WriteString(fmt.Sprintf("%.1f/10", result.SecurityScore.Value))
	output.WriteString(`</div>
                <div style="margin-top: 5px; font-weight: bold;">`)
	output.WriteString(result.SecurityScore.Risk)
	output.WriteString(`</div>
            </div>
        </div>
        
        <div class="tests-section">
            <h2>Resultados Detallados</h2>`)
	
	for _, test := range result.TestResults {
		statusClass := "test-passed"
		statusIcon := "✅"
		if test.Status != "Passed" {
			statusClass = "test-failed"
			statusIcon = "❌"
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
			statusClass, statusIcon, test.TestName, severityClass, test.Severity, test.Description))
		
		if len(test.Details) > 0 {
			output.WriteString(`
                    <div class="details">
                        <strong>Detalles:</strong>
                        <ul>`)
			for _, detail := range test.Details {
				output.WriteString(fmt.Sprintf("<li>%s</li>", detail))
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
            <ol>`)
		
		for _, rec := range result.Recommendations {
			output.WriteString(fmt.Sprintf("<li>%s</li>", rec))
		}
		
		output.WriteString(`
            </ol>
        </div>`)
	}
	
	output.WriteString(`
    </div>
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
