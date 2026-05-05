# SysPulse

![Status](https://img.shields.io/badge/status-active-success)
![Version](https://img.shields.io/badge/version-1.0-blue)
![License](https://img.shields.io/badge/license-academic-lightgrey)
![Made with](https://img.shields.io/badge/made%20with-HTML%20%7C%20CSS%20%7C%20JS-orange)

**SysPulse** es una plataforma web de monitoreo en tiempo real que permite supervisar múltiples equipos (PCs), visualizar su estado y generar reportes de forma centralizada.

---

## Descripción

SysPulse fue desarrollado como una solución para el monitoreo de equipos dentro de una red, permitiendo:

- Visualizar el estado de cada dispositivo  
- Analizar métricas del sistema  
- Ubicar equipos mediante mapa  
- Generar reportes exportables  

La aplicación está orientada a escenarios académicos, administrativos o de soporte técnico donde se requiere control y seguimiento de múltiples equipos.

---

##  Características principales

### Gestión de equipos
- Registro y visualización de PCs  
- Selección de equipos para ver detalles  
- Eliminación de dispositivos  

### Monitoreo en tiempo real
- Estado: **Online / Offline**  
- Último reporte recibido  
- Información del sistema  

### Mapa de equipos
- Visualización geográfica de dispositivos  
- Identificación por estado:  
  - 🟢 Online  
  - 🔴 Offline  

### Exportación de informes
- Formatos disponibles:
  - PDF  
  - Excel  
- Opciones:
  - Día único  
  - Rango de fechas  
- Incluye:
  - Estado de equipos  
  - Historial  
  - Datos detallados  

### Configuración personalizada
- Zona horaria  
- Idioma (Español / Inglés)  
- Tema:
  - Claro  
  - Oscuro  
  - Azul  

### Gestión de sesión
- Login de usuario  
- Confirmación al cerrar sesión  
- Redirección automática al login  

### Experiencia de usuario
- Alertas visuales modernas  
- Confirmaciones antes de acciones importantes  
- Interfaz limpia y amigable  

---

## Tecnologías utilizadas

- **Frontend:** HTML5, CSS3, JavaScript  
- **Backend:** Python (server.py)  
- **Mapas:** Google Maps (si está configurado)  
- **Reportes:** PDF y Excel  

---

---

## Instalación y ejecución

1. Clona el repositorio:

```bash
git clone https://github.com/tu-usuario/SysPulse.git

2. Ingresa al proyecto:
cd SysPulse

3. Ejecuta el servidor:
python server.py

4. Abre en el navegador:
http://127.0.0.1:8000

### Uso básico

1. Iinicia sesión en la plataforma
2. Visualiza o registra equipos
3. Selecciona un PC para ver detalles
4. Usa el dashboard para analizar métricas
5. Exporta reportes en PDF o Excel

