# VT IP Checker

Aplicación web estática para consultar **por lotes** direcciones IP en [VirusTotal](https://www.virustotal.com) y listar solo las que tienen **más de 2 IoC**.

VirusTotal (plan gratuito) no permite buscar varias IPs en una sola petición, así que la aplicación las consulta una por una, respetando el límite de 4 solicitudes por minuto.

## Funciones

- Entrada de hasta **10 IPs por consulta** (IPv4 e IPv6), separadas por línea, coma o espacio.
- Si se ingresan más de 10, aparece una **alerta** y el botón de análisis queda **deshabilitado**.
- Validación de formato, eliminación de duplicados y aviso de entradas no válidas.
- Filtro: solo se muestran las IPs con **más de 2 IoC** (`malicious + suspicious ≥ 3`).
- Cada IP con IoC incluye su **enlace de referencia** a VirusTotal.
- **Contadores**: IPs analizadas, IPs con problemas, IPs sin problemas e IPs con error de consulta.
- Sección de **informe de servicios involucrados** con la función de cada uno.
- Cancelación del análisis en curso y limpieza de la lista.

## Requisitos

- Una API key personal de VirusTotal (se obtiene gratis en tu cuenta de VirusTotal → *API key*).
- Un navegador moderno. No requiere instalación, Node.js ni servidor.

## Uso

1. Abre el sitio y pega tu API key.
2. Ingresa hasta 10 IPs.
3. Pulsa **Iniciar análisis**. Entre consultas se espera ~15 s, por lo que 10 IPs tardan unos 2,5 minutos.
4. Revisa la tabla de resultados y la sección de errores, si la hay.

## Estructura

```
vt-ip-checker/
├── index.html   # Interfaz y informe de servicios
├── styles.css   # Estilos
├── app.js       # Lógica: validación, consultas a la API, filtro y render
├── .nojekyll    # Evita que GitHub Pages procese el sitio con Jekyll
└── README.md
```

## Configuración

Las constantes están al inicio de [app.js](app.js):

| Constante        | Valor   | Descripción                                  |
| ---------------- | ------- | -------------------------------------------- |
| `MAX_IPS`        | `10`    | Máximo de IPs por consulta                   |
| `MIN_IOC`        | `3`     | Umbral: más de 2 IoC                         |
| `REQUEST_GAP_MS` | `15000` | Pausa entre consultas (plan gratuito: 4/min) |

## Despliegue en GitHub Pages

1. Crea un repositorio `vt-ip-checker` en GitHub (público o privado con Pages habilitado).
2. Sube estos archivos a la rama `main`.
3. Ve a **Settings → Pages**, elige **Deploy from a branch**, rama `main` y carpeta `/ (root)`.
4. El sitio quedará disponible en `https://<usuario>.github.io/vt-ip-checker/`.

## Seguridad y privacidad

- **No** incluyas la API key en el código ni en el repositorio. Cada usuario introduce la suya.
- La clave solo se envía a `www.virustotal.com`. Si marcas "Recordar", se guarda en `localStorage` de tu navegador.
- El sitio no tiene backend ni registra datos.

## Notas

- La cuota gratuita de VirusTotal es de 500 consultas al día; cada IP consume una.
- Si el navegador bloquea las peticiones por CORS, VirusTotal habrá cambiado su política; en ese caso se necesita un proxy intermedio.
- IoC se calcula con los veredictos `malicious` y `suspicious` de `last_analysis_stats`. Una IP que VirusTotal no conoce (HTTP 404) se cuenta como sin problemas.
