# OpenShift Operator API Usage

Herramienta en Bash y Python para revisar la actividad de las APIs declaradas por operadores instalados mediante OLM en OpenShift. Relaciona los eventos de auditoría del kube-apiserver con los CRDs de un CSV, identifica las identidades que hicieron las peticiones y compara la actividad observada con las instancias actuales.

El informe sirve como evidencia para revisar el uso del operador. La ausencia de peticiones o de instancias actuales no demuestra por sí sola que el operador se pueda retirar; esa decisión corresponde al cliente.

## Requisitos

- Bash.
- Python 3.10 o posterior; no requiere paquetes de Python externos.
- `oc` y una sesión autenticada contra el clúster para los modos `report` y `capture`.
- Permisos para consultar CSVs, CRDs, recursos personalizados y, en la captura completa, los logs de los nodos master.

El modo `analyze` trabaja en local y no necesita `oc` ni acceso al clúster.

## Uso rápido

Desde el directorio donde están los dos scripts, ejecuta:

```bash
./ocp-operator-api-usage.sh --help
```

Desde otro directorio, indica la ruta al lanzador. También se puede invocar directamente el analizador Python.

### Generar informes directamente desde el clúster

Muestra una lista interactiva de CSVs instalados y permite elegir uno o varios:

```bash
./ocp-operator-api-usage.sh report --days 30 --output-dir operator-reports
```

O selecciona los CSVs por nombre:

```bash
./ocp-operator-api-usage.sh report \
  --operator ejemplo-operator.v1.2.3 \
  --operator otro-operator.v4.5.6 \
  --days 30 \
  --output-dir operator-reports
```

Genera un Markdown por operador y un HTML consolidado. Los logs se descargan y analizan una vez por ejecución. Si un CSV aparece en más de un namespace, limita la búsqueda con `--namespace` o utiliza la selección interactiva.

### Capturar un snapshot completo

Con acceso al clúster, captura metadata, inventario de recursos y logs de auditoría disponibles:

```bash
./ocp-operator-api-usage.sh capture \
  --operator ejemplo-operator.v1.2.3 \
  --output-dir snapshot-ejemplo
```

El directorio debe ser nuevo. Después, el snapshot se puede analizar sin conexión:

```bash
./ocp-operator-api-usage.sh analyze \
  --snapshot-dir snapshot-ejemplo \
  --days 30 \
  --output informe-ejemplo.md
```

Se generan el informe Markdown y el HTML `informe-ejemplo.html`.

### Analizar logs descargados por separado

Primero crea metadata del operador mientras tengas acceso al clúster. `--metadata-only` omite la descarga de logs, pero guarda `metadata.json` e inventario:

```bash
./ocp-operator-api-usage.sh capture \
  --operator ejemplo-operator.v1.2.3 \
  --output-dir metadata-ejemplo \
  --metadata-only
```

Para consultar los nombres de los logs de auditoría disponibles en los nodos master:

```bash
oc adm node-logs --role=master --path=kube-apiserver/
```

Exporta cada archivo `audit*.log` que quieras analizar, usando el nodo y el nombre exacto que mostró el comando anterior. Por ejemplo:

```bash
mkdir -p logs-audit
NODE=master-0
FILE=audit.log
oc adm node-logs "$NODE" --path="kube-apiserver/$FILE" > "logs-audit/${NODE}__${FILE}"
```

Repite la exportación para los demás archivos disponibles. Se requieren permisos para leer los logs de los nodos. La cobertura temporal depende de los archivos que sigan retenidos y que se hayan exportado.

Analiza la carpeta de logs con el `metadata.json` correspondiente al CSV:

```bash
./ocp-operator-api-usage.sh analyze \
  --audit-dir logs-audit \
  --metadata metadata-ejemplo/metadata.json \
  --days 30 \
  --output informe-ejemplo.md
```

El análisis recorre la carpeta y sus subdirectorios. Acepta logs JSON por líneas y archivos comprimidos con extensión `.gz`. Esta forma de análisis procesa un operador por ejecución y genera Markdown y HTML.

## Contenido del informe

- Resumen de APIs/CRDs, instancias actuales y peticiones correctas o fallidas.
- Identidades, `userAgent`, namespaces, verbos y marcas de tiempo observadas.
- Ventana y rango temporal cubiertos por los logs, además de errores de captura o análisis.
- Recursos personalizados que existen en el momento de la captura.

Los logs de auditoría pueden contener identidades y otros datos operativos. Guarda los snapshots e informes con acceso restringido y revisa su contenido antes de compartirlos.

## Interpretación

- Una API puede tener peticiones aunque ya no queden instancias actuales de su CRD.
- Una petición fallida también demuestra que hubo un intento de acceso, aunque no que la operación tuviera éxito.
- Los eventos reflejan solo los archivos disponibles y la ventana analizada; su ausencia no prueba que el operador esté sin uso.
- Las identidades observadas ayudan a investigar dependencias, pero no determinan por sí solas si el operador es prescindible.

Consulta `./ocp-operator-api-usage.sh capture --help` y `./ocp-operator-api-usage.sh analyze --help` para ver las opciones disponibles.
