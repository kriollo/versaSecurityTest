# Catálogo de vulnerabilidades para evaluación de aplicaciones web

**Versión del documento:** 1.0\
**Fecha de referencia:** 2026-11-03\
**Idioma:** Español\
**Uso previsto:** base inicial para importar, clasificar y correlacionar
hallazgos en una aplicación de evaluación de seguridad web.

> **Alcance y precisión:** este documento es un catálogo de clases de
> vulnerabilidades, superficies de ataque y tecnologías que deben
> evaluarse. No representa una lista exhaustiva de CVE ni afirma que
> cada framework sea vulnerable a todas las clases indicadas. Los CVE,
> GHSA y OSV deben importarse desde fuentes actualizadas y conservar sus
> rangos de versiones afectados.

## 1. Modelo conceptual

Separar los siguientes conceptos en el sistema:

-   **Debilidad (CWE):** clase o causa técnica del defecto.
-   **Vulnerabilidad (CVE/GHSA/OSV):** defecto identificado en un
    producto o paquete concreto.
-   **Riesgo (OWASP):** categoría de riesgo de aplicación o API.
-   **Regla de detección:** procedimiento estático, dinámico o de
    configuración que busca evidencia.
-   **Hallazgo:** resultado de una ejecución de escaneo, con evidencia,
    alcance, confianza y estado.
-   **Activo:** dominio, aplicación, servidor, repositorio, imagen,
    paquete o endpoint evaluado.

No convertir automáticamente una categoría OWASP o CWE en un CVE.
Tampoco inferir que un producto está afectado únicamente por detectar su
nombre o una versión aproximada.

## 2. Clasificación general de vulnerabilidades

  ---------------------------------------------------------------------------------
  ID                Vulnerabilidad     Descripción resumida     Severidad
                                                                orientativa
  ----------------- ------------------ ------------------------ -------------------
  WEB-001           SQL Injection      Entrada no confiable     Crítica
                    (SQLi)             altera la estructura de  
                                       una consulta SQL.        

  WEB-002           Cross-Site         Datos controlados por    Alta
                    Scripting (XSS)    atacante se ejecutan     
                                       como script en el        
                                       navegador.               

  WEB-003           Cross-Site Request El navegador autenticado Alta
                    Forgery (CSRF)     de una víctima envía     
                                       acciones no deseadas.    

  WEB-004           Server-Side        El servidor realiza      Alta/Crítica
                    Request Forgery    solicitudes a destinos   
                    (SSRF)             no autorizados.          

  WEB-005           Remote Code        Un atacante logra        Crítica
                    Execution (RCE)    ejecutar código en el    
                                       sistema afectado.        

  WEB-006           Local File         La aplicación incluye o  Alta
                    Inclusion (LFI)    procesa archivos locales 
                                       no autorizados.          

  WEB-007           Remote File        La aplicación incluye    Crítica
                    Inclusion (RFI)    recursos remotos         
                                       controlados por          
                                       terceros.                

  WEB-008           Path Traversal     Manipulación de rutas    Alta
                                       para salir del           
                                       directorio permitido.    

  WEB-009           Broken Access      Los controles de         Alta/Crítica
                    Control            autorización no          
                                       restringen correctamente 
                                       las acciones.            

  WEB-010           IDOR / BOLA        Un usuario accede a      Alta
                                       objetos ajenos           
                                       manipulando              
                                       identificadores.         

  WEB-011           Authentication     Se omite o evita el      Crítica
                    Bypass             mecanismo de             
                                       autenticación.           

  WEB-012           Session Fixation   El atacante fuerza o     Alta
                                       reutiliza un             
                                       identificador de sesión  
                                       conocido.                

  WEB-013           Session Hijacking  Robo o reutilización no  Alta/Crítica
                                       autorizada de una sesión 
                                       válida.                  

  WEB-014           Open Redirect      Redirección controlada   Media
                                       hacia un destino externo 
                                       no confiable.            

  WEB-015           HTTP Response      Datos no confiables      Alta
                    Splitting          alteran límites de       
                                       encabezados/respuestas   
                                       HTTP.                    

  WEB-016           CRLF Injection     Inserción de CR/LF en    Media/Alta
                                       contextos que afectan    
                                       encabezados o            
                                       protocolos.              

  WEB-017           OS Command         Entrada no confiable     Crítica
                    Injection          altera comandos del      
                                       sistema operativo.       

  WEB-018           LDAP Injection     Entrada no confiable     Alta
                                       modifica filtros o       
                                       consultas LDAP.          

  WEB-019           XML External       Parser XML procesa       Alta
                    Entity (XXE)       entidades externas       
                                       peligrosas.              

  WEB-020           Insecure           Se deserializan datos    Alta/Crítica
                    Deserialization    manipulables sin         
                                       controles suficientes.   

  WEB-021           Server-Side        Entrada no confiable se  Crítica
                    Template Injection interpreta como          
                    (SSTI)             expresión de plantilla.  

  WEB-022           Unrestricted File  Se aceptan archivos      Alta/Crítica
                    Upload             peligrosos o se          
                                       almacenan en ubicaciones 
                                       ejecutables.             

  WEB-023           Information        Se expone información    Media/Alta
                    Disclosure         interna, sensible o de   
                                       depuración.              

  WEB-024           Security           Configuración insegura   Variable
                    Misconfiguration   de servidor, framework,  
                                       nube o aplicación.       

  WEB-025           Missing Security   Ausencia o configuración Informativa/Media
                    Headers            incorrecta de            
                                       encabezados defensivos.  

  WEB-026           Clickjacking       La interfaz puede ser    Media
                                       embebida para inducir    
                                       acciones no deseadas.    

  WEB-027           Cryptographic      Cifrado, almacenamiento  Alta
                    Failures           o gestión criptográfica  
                                       deficientes.             

  WEB-028           Weak Password      Política de contraseñas  Media
                    Policy             insuficiente para el     
                                       riesgo del sistema.      

  WEB-029           Brute Force /      Intentos automatizados   Alta
                    Credential         de autenticación sin     
                    Stuffing           defensas adecuadas.      

  WEB-030           Denial of Service  Consumo de recursos o    Alta
                    (DoS)              indisponibilidad         
                                       provocada por            
                                       solicitudes.             

  WEB-031           Regular Expression Expresiones regulares    Media/Alta
                    DoS (ReDoS)        con tiempo de ejecución  
                                       desproporcionado.        

  WEB-032           Cache Poisoning    Manipulación de          Alta
                                       respuestas almacenadas   
                                       en caché.                

  WEB-033           HTTP Request       Diferencias de           Alta/Crítica
                    Smuggling          interpretación HTTP      
                                       entre proxy y servidor   
                                       de origen.               

  WEB-034           Race Condition     Operaciones concurrentes Variable
                                       producen estados         
                                       inconsistentes           
                                       explotables.             

  WEB-035           Mass Assignment    Campos sensibles pueden  Alta
                                       modificarse mediante     
                                       asignación automática.   

  WEB-036           Prototype          Modificación de          Alta
                    Pollution          prototipos JavaScript    
                                       afecta objetos o lógica. 

  WEB-037           CORS               Orígenes o credenciales  Media/Alta
                    Misconfiguration   se autorizan de forma    
                                       excesiva.                

  WEB-038           JWT Validation     Validación incorrecta de Alta
                    Failure            firma, algoritmo,        
                                       emisor, audiencia o      
                                       expiración.              

  WEB-039           Rate Limit Bypass  Se evaden límites de     Media/Alta
                                       solicitudes o controles  
                                       antiabuso.               

  WEB-040           Secrets Exposure   Secretos quedan          Alta/Crítica
                                       expuestos en             
                                       repositorios, bundles,   
                                       logs o archivos          
                                       públicos.                

  WEB-041           Dependency         Dependencia utilizada    Según CVSS/contexto
                    Vulnerability      contiene un aviso de     
                                       seguridad aplicable.     

  WEB-042           Dependency         Resolución de paquetes   Alta
                    Confusion          permite instalar un      
                                       paquete no confiable.    

  WEB-043           Supply Chain       Paquete, pipeline,       Alta/Crítica
                    Compromise         artefacto o proveedor de 
                                       software comprometido.   

  WEB-044           Host Header        Encabezado Host no       Media/Alta
                    Injection          confiable altera         
                                       generación de enlaces o  
                                       enrutamiento.            

  WEB-045           DNS Rebinding      Cambios de resolución    Alta
                                       DNS permiten acceder a   
                                       servicios desde un       
                                       contexto no previsto.    

  WEB-046           WebSocket          Conexiones o mensajes no Alta
                    Authorization      validan identidad,       
                    Failure            origen y permisos.       

  WEB-047           GraphQL Abuse      Autorización,            Variable
                                       profundidad, complejidad 
                                       o introspección no se    
                                       controlan adecuadamente. 

  WEB-048           TLS                Protocolos, suites,      Media/Alta
                    Misconfiguration   certificados o           
                                       parámetros TLS son       
                                       inseguros.               

  WEB-049           Improper Error     Excepciones y errores se Variable
                    Handling           gestionan de forma que   
                                       filtran datos o alteran  
                                       seguridad.               

  WEB-050           Insufficient       Eventos relevantes no se Variable
                    Logging and        registran, supervisan o  
                    Alerting           alertan adecuadamente.   
  ---------------------------------------------------------------------------------

**Nota:** la severidad de la tabla es orientativa. El resultado real
depende de explotabilidad, impacto, exposición, privilegios, datos
afectados y controles compensatorios.

## 3. OWASP Top 10:2025

  -----------------------------------------------------------------------
  Código                  Categoría oficial       Qué evaluar
  ----------------------- ----------------------- -----------------------
  A01:2025                Broken Access Control   Autorización por
                                                  objeto, función, tenant
                                                  y contexto; IDOR/BOLA.

  A02:2025                Security                Defaults inseguros,
                          Misconfiguration        servicios expuestos,
                                                  permisos, errores y
                                                  cabeceras.

  A03:2025                Software Supply Chain   Dependencias,
                          Failures                repositorios, build,
                                                  CI/CD, artefactos y
                                                  proveedores.

  A04:2025                Cryptographic Failures  Cifrado, hashes,
                                                  secretos, TLS y gestión
                                                  de claves.

  A05:2025                Injection               SQL, NoSQL, OS command,
                                                  LDAP, XPath, SSTI y
                                                  otros intérpretes.

  A06:2025                Insecure Design         Ausencia de controles
                                                  de seguridad desde el
                                                  diseño.

  A07:2025                Authentication Failures Sesiones, credenciales,
                                                  MFA, recuperación y
                                                  autenticación.

  A08:2025                Software or Data        Integridad de
                          Integrity Failures      actualizaciones,
                                                  serialización,
                                                  deserialización y
                                                  datos.

  A09:2025                Security Logging and    Registro, trazabilidad,
                          Alerting Failures       detección y respuesta.

  A10:2025                Mishandling of          Errores, fallos
                          Exceptional Conditions  parciales, estados
                                                  inesperados y
                                                  agotamiento de
                                                  recursos.
  -----------------------------------------------------------------------

Referencia: https://top10.owasp.org/2025/es/

## 4. Tecnologías y superficies que deben evaluarse

Las siguientes matrices son mapas de cobertura para diseñar reglas. No
son afirmaciones de vulnerabilidades confirmadas en cada producto.

### 4.1 Servidores web y proxy

  --------------------------------------------------------------------------
  Producto                Componentes/superficies    Clases de riesgo a
                                                     evaluar
  ----------------------- -------------------------- -----------------------
  Apache HTTP Server      `mod_proxy`,               Request smuggling, DoS,
                          `mod_rewrite`,             buffer errors, path
                          `mod_http2`, `mod_ssl`,    handling, SSRF por
                          `mod_dav`, `mod_cgi`,      proxy, exposición de
                          `mod_headers`, `mod_alias` información, TLS y
                                                     configuración

  Nginx                   `ngx_http_proxy_module`,   Request smuggling, DoS,
                          `rewrite`, `alias`,        path traversal por
                          HTTP/2, HTTP/3, `ssl`,     configuración, SSRF por
                          `fastcgi`, `uwsgi`,        proxy, errores de
                          `scgi`, `dav`              memoria, TLS y
                                                     configuración

  Caddy                   Reverse proxy, TLS         Control de acceso,
                          automático, handlers,      proxy, TLS, path
                          plugins                    handling, configuración
                                                     y dependencias

  Microsoft IIS           Request Filtering, ISAPI,  Request smuggling, path
                          ASP.NET integration,       handling,
                          WebDAV                     autenticación,
                                                     configuración y
                                                     exposición

  HAProxy                 Frontend/backend, ACL,     Request smuggling, ACL
                          HTTP parser, TLS           bypass, exposición de
                                                     backend, TLS y DoS

  Traefik                 Routers, middlewares,      Dashboard expuesto,
                          providers, dashboard       control de acceso,
                                                     routing, TLS y
                                                     configuración
  --------------------------------------------------------------------------

### 4.2 PHP y frameworks PHP

  -------------------------------------------------------------------------
  Producto                Componentes/superficies   Clases de riesgo a
                                                    evaluar
  ----------------------- ------------------------- -----------------------
  PHP Runtime             Streams, wrappers,        RCE, file inclusion,
                          sesiones, FFI,            path traversal,
                          extensiones, funciones de deserialización,
                          proceso, configuración    command injection,
                                                    exposición de
                                                    configuración

  Laravel                 Eloquent, Query Builder,  SQLi, XSS, mass
                          Blade, Validation,        assignment,
                          Filesystem, Signed URLs,  autorización, CSRF,
                          Sanctum, Passport,        upload, path traversal,
                          Middleware                tokens y configuración

  Symfony                 HttpFoundation,           Autorización,
                          HttpKernel, Security,     autenticación, SSTI,
                          Routing, Serializer,      SSRF, deserialización,
                          Yaml, Twig, HttpClient,   parser DoS, cache
                          Cache                     poisoning y routing

  CodeIgniter             Query Builder, Input,     SQLi, XSS, CSRF,
                          Session, Upload, Router   sesión, upload y
                                                    autorización

  CakePHP                 ORM, Router, Middleware,  SQLi, XSS, CSRF,
                          Authentication,           autorización y
                          Authorization,            deserialización
                          FormProtection            

  Yii                     ActiveRecord, DB, Upload, SQLi, XSS, CSRF,
                          URL Manager,              autorización, upload y
                          Serialization             deserialización

  Laminas                 MVC, Diactoros, DB,       SQLi, XSS, SSRF, XML,
                          Router, Authentication,   autenticación y
                          XML                       autorización

  Slim                    Routing, Middleware,      Autorización, XSS,
                          PSR-7, Error Middleware   CSRF, SSRF y errores

  Phalcon                 ORM, Volt, Router,        SQLi, SSTI, XSS, sesión
                          Security, Session         y autorización

  WordPress               Core, plugins, themes,    XSS, SQLi, CSRF,
                          REST API, XML-RPC         escalada de
                                                    privilegios, upload y
                                                    vulnerabilidades de
                                                    plugins

  Drupal                  Core, módulos, themes,    RCE, XSS, SQLi, bypass
                          REST, render API          de acceso, upload y
                                                    dependencias

  TYPO3                   Core, extensiones,        RCE, XSS, SQLi,
                          backend, frontend         autenticación,
                                                    autorización y
                                                    exposición
  -------------------------------------------------------------------------

### 4.3 JavaScript, Node.js y frameworks frontend/backend

  -------------------------------------------------------------------------
  Producto                Componentes/superficies   Clases de riesgo a
                                                    evaluar
  ----------------------- ------------------------- -----------------------
  Node.js Runtime         `child_process`, `fs`,    Command injection, path
                          `vm`, HTTP, TLS, permisos traversal, SSRF, DoS,
                                                    exposición de secretos

  Express.js              Middleware, Router,       XSS, CSRF, SSRF, open
                          parsers, sesiones, proxy  redirect, prototype
                                                    pollution, trust proxy
                                                    y autorización

  Next.js                 SSR, Server Actions,      SSRF, autorización,
                          Route Handlers,           XSS, cache poisoning,
                          Middleware, Image         bypass y dependencias
                          Optimization, cache       

  Nuxt                    SSR, Nitro, server        SSRF, XSS, exposición
                          routes, plugins, runtime  de secretos, path
                          config                    handling y dependencias

  NestJS                  Guards, interceptors,     Autenticación,
                          pipes, decorators,        autorización, mass
                          adapters                  assignment, validación
                                                    y SSRF

  Fastify                 Plugins, hooks, schemas,  Validación, prototype
                          serializers               pollution, DoS, parsing
                                                    y autorización

  Koa                     Middleware, context,      XSS, CSRF, headers,
                          cookies, proxy            sesiones y autorización

  Hapi                    Routes, validation, auth  Validación,
                          strategies, plugins       autenticación, SSRF y
                                                    exposición

  Sails.js                Policies, actions, ORM,   Autorización, SQL/NoSQL
                          sockets                   injection, XSS y
                                                    WebSocket

  Meteor                  Methods, publications,    Autorización,
                          MongoDB, DDP              exposición de datos,
                                                    NoSQL injection y XSS

  AdonisJS                Auth, Shield, Lucid ORM,  SQLi, CSRF,
                          validators                autorización, sesión y
                                                    mass assignment

  React                   DOM sinks, rendering,     XSS, DOM injection,
                          dependencies, hydration   dependencias y
                                                    exposición de secretos

  Vue.js                  Template compilation,     XSS, SSRF en SSR,
                          `v-html`, SSR, plugins    exposición de secretos
                                                    y dependencias

  Angular                 DOM sanitization,         XSS, bypass de
                          templates, interceptors,  sanitización,
                          dependencies              autorización y
                                                    dependencias
  -------------------------------------------------------------------------

### 4.4 Python y frameworks

  -------------------------------------------------------------------------
  Producto                Componentes/superficies   Clases de riesgo a
                                                    evaluar
  ----------------------- ------------------------- -----------------------
  Python Runtime          `pickle`, `subprocess`,   Deserialización,
                          `eval`, `exec`, `os`,     command injection,
                          `pathlib`, XML            ejecución dinámica,
                                                    path traversal y XXE

  Django                  ORM, Templates,           SQLi, XSS, CSRF, SSRF,
                          Middleware, Admin,        autorización, sesión,
                          Upload, Sessions, Cache   cache y upload

  Flask                   Jinja2, Werkzeug,         SSTI, XSS, exposición
                          sessions, debug server,   del debugger, sesión y
                          blueprints                path traversal

  FastAPI                 Dependencies, Pydantic,   Autorización,
                          OpenAPI, UploadFile,      validación, SSRF, DoS y
                          middleware                JWT

  Starlette               Routing, middleware,      Autorización, parsing
                          sessions, responses       HTTP, sesión, DoS y
                                                    path handling

  Tornado                 Request handlers,         XSS, CSRF, WebSocket,
                          templates, cookies,       autenticación y DoS
                          WebSocket                 

  Pyramid                 Traversal, ACL, sessions, Autorización, XSS, CSRF
                          views                     y sesiones

  Falcon                  Middleware, hooks,        Autenticación,
                          request parsing           autorización, parsing y
                                                    SSRF

  Sanic                   Routing, middleware,      Autorización, parsing,
                          WebSocket                 DoS y SSRF

  Bottle                  Templates, routing, debug SSTI, XSS, exposición
                          mode                      de debug y path
                                                    traversal
  -------------------------------------------------------------------------

### 4.5 Go y frameworks

  -------------------------------------------------------------------------
  Producto                Componentes/superficies   Clases de riesgo a
                                                    evaluar
  ----------------------- ------------------------- -----------------------
  Go Runtime / stdlib     `net/http`, `os/exec`,    Request smuggling,
                          `os`, `filepath`,         command injection, path
                          `crypto/tls`, `encoding`  traversal, TLS y DoS

  Gin                     Middleware, binding,      Autorización,
                          sessions, proxy           validación, XSS, SSRF y
                                                    configuración de proxy

  Echo                    Middleware, binder,       Autorización,
                          router, static files      validación, path
                                                    traversal, XSS y SSRF

  Fiber                   fasthttp, middleware,     Parsing HTTP, headers,
                          static, proxy             path traversal y DoS

  Beego                   ORM, controllers,         SQLi, XSS, CSRF,
                          sessions, templates       sesiones y autorización

  Chi                     Router, middleware,       Autorización, SSRF y
                          context                   middleware

  Buffalo                 ORM, templates, sessions, SQLi, XSS, CSRF, upload
                          uploads                   y sesión

  Revel                   Controllers, filters,     XSS, CSRF, autorización
                          templates                 y configuración

  Iris                    Middleware, sessions,     Autorización, path
                          static files              traversal, XSS y DoS
  -------------------------------------------------------------------------

## 5. Vulnerabilidades de librerías y runtimes

  -----------------------------------------------------------------------
  Ecosistema              Componente/librería     Riesgos a evaluar
  ----------------------- ----------------------- -----------------------
  JavaScript              `eval`, `Function`      Ejecución dinámica de
                                                  código

  JavaScript              `innerHTML`,            DOM XSS
                          `outerHTML`,            
                          `document.write`        

  JavaScript              Lodash y librerías de   Prototype pollution
                          merge                   según versión y uso

  Node.js                 `child_process`         Command injection

  Node.js                 `fs`, `path`            Path traversal y
                                                  exposición de archivos

  Node.js                 HTTP clients            SSRF y validación de
                                                  destinos

  Python                  `pickle`                Deserialización
                                                  insegura

  Python                  PyYAML                  Carga YAML insegura
                                                  según loader y uso

  Python                  `subprocess`,           Command injection
                          `os.system`             

  Python                  Jinja2                  SSTI según el origen de
                                                  las plantillas

  Python                  XML parsers             XXE según
                                                  parser/configuración

  Go                      `os/exec`               Command injection

  Go                      `net/http`              SSRF, parsing y request
                                                  smuggling

  Go                      `filepath`, `os`        Path traversal y
                                                  permisos

  Go                      `math/rand`             Aleatoriedad no
                                                  criptográfica cuando se
                                                  usa para secretos

  PHP                     `unserialize`           Deserialización
                                                  insegura

  PHP                     `include`, `require`    File inclusion

  PHP                     `exec`, `system`,       Command injection
                          `shell_exec`,           
                          `proc_open`             

  PHP                     Streams y wrappers      Acceso a recursos según
                                                  configuración

  PHP                     `move_uploaded_file`    Riesgos de carga y
                                                  almacenamiento de
                                                  archivos
  -----------------------------------------------------------------------

La presencia de una función sensible no constituye por sí sola una
vulnerabilidad. La regla debe analizar flujo de datos, origen de
entrada, validación, sanitización, contexto de uso y controles de
autorización.

## 6. Identificadores y estándares

  -----------------------------------------------------------------------
  Estándar                            Uso
  ----------------------------------- -----------------------------------
  CVE                                 Identificador público de una
                                      vulnerabilidad concreta.

  CWE                                 Clasificación de debilidades de
                                      software.

  CVSS                                Puntuación y vector de severidad
                                      técnica.

  CPE                                 Identificación normalizada de
                                      productos/plataformas.

  PURL                                Identificación de paquetes y
                                      componentes de software.

  GHSA                                Identificador de GitHub Security
                                      Advisory.

  OSV                                 Esquema y base de vulnerabilidades
                                      orientada a paquetes/versiones.

  KEV                                 Catálogo CISA de vulnerabilidades
                                      explotadas conocidas.

  OWASP Top 10                        Categorías de riesgos de
                                      aplicaciones web.

  OWASP API Security Top 10           Categorías de riesgos específicos
                                      de APIs.
  -----------------------------------------------------------------------

## 7. Fuentes de datos recomendadas

Priorizar fuentes estructuradas y avisos oficiales. Mantener fecha de
sincronización, origen y referencia original.

  -----------------------------------------------------------------------------------------------------------------------
  Fuente                  Cobertura               URL
  ----------------------- ----------------------- -----------------------------------------------------------------------
  NVD                     CVE, CVSS, CPE, CWE y   https://nvd.nist.gov/
                          referencias             

  NVD API 2.0             Consulta programática   https://nvd.nist.gov/developers/vulnerabilities
                          de CVE                  

  GitHub Advisory         GHSA, CVE y paquetes    https://github.com/advisories
  Database                por ecosistema          

  GitHub Advisory REST    Consulta programática   https://docs.github.com/en/rest/security-advisories/global-advisories
  API                     de advisories           

  OSV.dev                 Vulnerabilidades por    https://osv.dev/
                          paquete y versión       

  OSV API                 Consultas individuales  https://google.github.io/osv.dev/api/
                          y batch                 

  MITRE CWE               Taxonomía de            https://cwe.mitre.org/
                          debilidades             

  CISA KEV                Vulnerabilidades        https://www.cisa.gov/known-exploited-vulnerabilities-catalog
                          explotadas en campañas  
                          reales                  

  OWASP Top 10            Riesgos generales de    https://top10.owasp.org/2025/es/
                          aplicaciones            

  OWASP API Security      Riesgos de APIs         https://owasp.org/www-project-api-security/

  Apache HTTP Server      Avisos oficiales httpd  https://httpd.apache.org/security/vulnerabilities_24.html
                          2.4                     

  Nginx                   Avisos oficiales        https://nginx.org/en/security_advisories.html

  Laravel                 Avisos del framework    https://github.com/laravel/framework/security/advisories

  Symfony                 Avisos del framework    https://github.com/symfony/symfony/security/advisories

  Django                  Releases de seguridad   https://www.djangoproject.com/weblog/

  Go Vulnerability        Vulnerabilidades del    https://vuln.go.dev/
  Database                ecosistema Go           
  -----------------------------------------------------------------------------------------------------------------------

### 7.1 Ejemplos de endpoints

**OSV: consultar un paquete y una versión**

`POST https://api.osv.dev/v1/query`

Ejemplo de cuerpo:

``` json
{
  "package": {
    "name": "laravel/framework",
    "ecosystem": "Packagist"
  },
  "version": "VERSION_A_CONSULTAR"
}
```

**OSV: consulta batch**

`POST https://api.osv.dev/v1/querybatch`

Permite consultar múltiples paquetes/versiones en una sola solicitud.
Consultar documentación oficial para esquema y paginación.

**NVD API 2.0**

`GET https://services.nvd.nist.gov/rest/json/cves/2.0`

Permite filtrar por identificador CVE, fechas y otros parámetros.
Respetar límites de uso, paginación y requisitos de API key.

**GitHub Advisory Database**

`GET https://api.github.com/advisories`

Permite filtrar avisos globales por ecosistema, severidad, identificador
y otros parámetros documentados. Usar autenticación cuando corresponda y
respetar rate limits.

## 8. Modelo de datos sugerido para PostgreSQL

No almacenar todos los datos en una única tabla. Separar entidades,
identificadores, rangos afectados, fuentes, reglas y resultados.

  -----------------------------------------------------------------------
  Tabla                               Propósito
  ----------------------------------- -----------------------------------
  `security_vulnerabilities`          Registro canónico de
                                      vulnerabilidades.

  `security_identifiers`              CVE, GHSA, OSV y otros
                                      identificadores asociados.

  `security_products`                 Fabricantes, productos y
                                      frameworks.

  `security_package_coordinates`      Ecosistema, nombre de paquete y
                                      PURL.

  `security_affected_ranges`          Versiones o commits afectados.

  `security_fixed_versions`           Versiones que corrigen el defecto.

  `security_weaknesses`               CWE y relaciones con
                                      vulnerabilidades.

  `security_categories`               OWASP y categorías internas.

  `security_sources`                  Fuentes y conectores de datos.

  `security_source_records`           Identificador externo, hash y
                                      payload original.

  `security_detection_rules`          Reglas SAST, DAST, configuración y
                                      fingerprinting.

  `security_scans`                    Ejecuciones de evaluación.

  `security_findings`                 Hallazgos de cada ejecución.

  `security_evidence`                 Evidencias asociadas a hallazgos.

  `security_exceptions`               Excepciones justificadas y falsos
                                      positivos revisados.
  -----------------------------------------------------------------------

### 8.1 Campos mínimos de `security_vulnerabilities`

  -----------------------------------------------------------------------
  Campo                   Tipo orientativo        Descripción
  ----------------------- ----------------------- -----------------------
  `id`                    UUID                    Identificador interno.

  `canonical_id`          VARCHAR                 Identificador
                                                  preferido, por ejemplo
                                                  CVE o GHSA.

  `title`                 TEXT                    Título.

  `description`           TEXT                    Descripción
                                                  normalizada.

  `severity`              VARCHAR                 CRITICAL, HIGH, MEDIUM,
                                                  LOW, UNKNOWN.

  `cvss_score`            NUMERIC(3,1)            Puntuación CVSS si
                                                  existe.

  `cvss_vector`           TEXT                    Vector CVSS original.

  `published_at`          TIMESTAMPTZ             Publicación.

  `modified_at`           TIMESTAMPTZ             Última modificación en
                                                  origen.

  `source_updated_at`     TIMESTAMPTZ             Última sincronización
                                                  local.

  `withdrawn_at`          TIMESTAMPTZ NULL        Retirada, si
                                                  corresponde.

  `status`                VARCHAR                 ACTIVE, WITHDRAWN,
                                                  DISPUTED, REVIEW.
  -----------------------------------------------------------------------

### 8.2 Campos de un hallazgo

-   `scan_id`
-   `asset_id`
-   `rule_id`
-   `vulnerability_id`, nullable cuando sea una debilidad sin CVE.
-   `target`
-   `parameter_or_component`
-   `severity`
-   `confidence`
-   `status`
-   `evidence_summary`
-   `evidence_reference`
-   `first_seen_at`
-   `last_seen_at`
-   `remediation`
-   `verified_at`

Conservar la evidencia de forma segura. Redactar tokens, cookies,
contraseñas, datos personales y secretos antes de persistir o exportar.

## 9. Formato normalizado de importación

Ejemplo orientativo de registro interno en JSON:

``` json
{
  "schema_version": "1.0",
  "record_type": "vulnerability",
  "identifiers": [
    {
      "type": "CVE",
      "value": "CVE-YYYY-NNNNN"
    }
  ],
  "title": "Título original de la fuente",
  "description": "Descripción original o normalizada",
  "severity": {
    "level": "UNKNOWN",
    "cvss_version": null,
    "score": null,
    "vector": null
  },
  "weaknesses": [],
  "affected": [
    {
      "ecosystem": "Packagist",
      "package": "vendor/package",
      "purl": null,
      "introduced": "1.0.0",
      "fixed": "1.2.3"
    }
  ],
  "references": [],
  "source": {
    "name": "OSV",
    "record_id": "ID_ORIGINAL",
    "url": "https://osv.dev/",
    "modified_at": null
  },
  "metadata": {
    "imported_at": null,
    "raw_payload_hash": null,
    "normalization_version": "1.0"
  }
}
```

Este JSON es una plantilla, no un registro real. No importar los
identificadores de ejemplo como vulnerabilidades válidas.

## 10. Reglas de correlación y evaluación

1.  Identificar el activo y su tecnología con evidencia.
2.  Determinar versión exacta cuando sea posible.
3.  Identificar paquetes usando lockfiles y coordenadas de paquete.
4.  Consultar NVD, OSV y GitHub Advisory Database.
5.  Comparar rangos afectados utilizando reglas de versiones específicas
    del ecosistema.
6.  Verificar condiciones de configuración y módulos requeridos.
7.  Correlacionar con CWE y categorías OWASP.
8.  Ejecutar pruebas dinámicas autorizadas cuando corresponda.
9.  Guardar evidencia reproducible y nivel de confianza.
10. Calcular riesgo contextual sin reemplazar el CVSS original.

### Reglas críticas

-   No comparar versiones como cadenas de texto.
-   No asumir que `2.4.9` es superior a `2.4.10` mediante comparación
    lexicográfica.
-   No ignorar sufijos, prereleases, versiones de distribución ni
    backports.
-   No afirmar que una vulnerabilidad es explotable solamente porque el
    producto está instalado.
-   No marcar como corregida una vulnerabilidad por una versión que no
    esté incluida en el rango corregido del aviso.
-   No deduplicar CVE, GHSA y OSV por título; utilizar identificadores y
    relaciones explícitas.
-   Mantener historial de cambios y payload original.
-   Diferenciar `NOT_AFFECTED`, `AFFECTED`, `FIXED`, `UNKNOWN` y
    `UNDER_REVIEW`.
-   No ejecutar pruebas destructivas en producción.
-   Ejecutar DAST únicamente contra activos con autorización explícita.

## 11. Herramientas complementarias

  -----------------------------------------------------------------------------------------------
  Herramienta             Uso                     URL
  ----------------------- ----------------------- -----------------------------------------------
  OWASP ZAP               DAST y pruebas de       https://www.zaproxy.org/
                          aplicaciones web        

  Trivy                   Dependencias, imágenes, https://trivy.dev/
                          IaC y configuración     

  Semgrep                 SAST y reglas           https://semgrep.dev/
                          personalizadas          

  OSV-Scanner             Análisis de             https://github.com/google/osv-scanner
                          dependencias basado en  
                          OSV                     

  Composer Audit          Auditoría de            https://getcomposer.org/doc/03-cli.md#audit
                          dependencias PHP        

  npm audit               Auditoría de            https://docs.npmjs.com/cli/commands/npm-audit
                          dependencias npm        

  pip-audit               Auditoría de paquetes   https://github.com/pypa/pip-audit
                          Python                  

  govulncheck             Análisis de             https://go.dev/doc/security/vuln/
                          vulnerabilidades en Go  
  -----------------------------------------------------------------------------------------------

## 12. Referencias verificadas para esta edición

-   OWASP Top 10:2025: https://top10.owasp.org/2025/es/
-   NVD: https://nvd.nist.gov/
-   Apache HTTP Server 2.4 Security:
    https://httpd.apache.org/security/vulnerabilities_24.html
-   Nginx Security Advisories:
    https://nginx.org/en/security_advisories.html
-   Laravel Framework Advisories:
    https://github.com/laravel/framework/security/advisories
-   Symfony Advisories:
    https://github.com/symfony/symfony/security/advisories
-   OSV API: https://google.github.io/osv.dev/api/
-   GitHub Advisory Database: https://github.com/advisories
-   MITRE CWE: https://cwe.mitre.org/
-   CISA KEV:
    https://www.cisa.gov/known-exploited-vulnerabilities-catalog
-   Go Vulnerability Database: https://vuln.go.dev/

## 13. Mantenimiento del catálogo

Este documento debe tratarse como catálogo de taxonomía y diseño, no
como feed de vulnerabilidades en tiempo real.

Proceso recomendado:

-   Sincronización periódica de NVD, OSV y GitHub Advisories.
-   Consulta de avisos oficiales de fabricantes.
-   Registro de fecha de última sincronización por fuente.
-   Reintentos controlados y paginación.
-   Deduplicación por identificadores y referencias.
-   Conservación del payload original.
-   Versionado del esquema de normalización.
-   Pruebas de regresión para rangos de versiones.
-   Revisión manual de avisos disputados, retirados o incompletos.

**Fin del documento.**
