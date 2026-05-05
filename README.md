# SysPulse

![Status](https://img.shields.io/badge/status-active-success)  
![Version](https://img.shields.io/badge/version-5.0-blue)  
![Made with](https://img.shields.io/badge/made%20with-HTML%20%7C%20CSS%20%7C%20JS-orange)

---

## Descripción

**SysPulse** es una plataforma web de monitoreo en tiempo real que permite supervisar múltiples equipos (PCs), visualizar su estado y generar reportes de forma centralizada.

Fue desarrollada como una solución para el monitoreo de equipos dentro de una red, permitiendo:

- Visualizar el estado de cada dispositivo  
- Analizar métricas del sistema  
- Ubicar equipos mediante mapa  
- Generar reportes exportables  

---

## Características principales

### Gestión de equipos
- Registro y visualización de PCs  
- Selección de equipos  
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
- Generación en **PDF y Excel**  
- Consulta por día o rango de fechas  
- Incluye estado, historial y métricas  

### Configuración
- Zona horaria  
- Idioma (Español / Inglés)  
- Tema (Claro, Oscuro, Azul)  

### Seguridad
- Inicio de sesión  
- Confirmación de acciones críticas  
- Cierre de sesión seguro  

---

## Tecnologías utilizadas

- HTML5  
- CSS3  
- JavaScript  
- Python (server.py)  
- Google Maps  

---

## Estructura del proyecto

```
SysPulse/
│
├── pc-agent/
├── pc-monitor/
├── templates/
├── static/
├── server.py
└── README.md
```

---

## Instalación y ejecución

Clona el repositorio:

```bash
git clone https://github.com/tu-usuario/SysPulse.git
```

Ingresa al proyecto:

```bash
cd SysPulse
```

Ejecuta el servidor:

```bash
python server.py
```

Abre en el navegador:

```
http://127.0.0.1:8000
```

---

## Uso básico

- Inicia sesión en la plataforma  
- Visualiza o registra equipos  
- Selecciona un PC para ver detalles  
- Usa el dashboard para analizar métricas  
- Exporta reportes en PDF o Excel  

---

## Autores

**Jesús David Arbelaez Castro**  
 jesus.arbelaez00@usc.edu.co  
 3113437723  

**Joan Sebastián Aguirre Drombo**  
 joan.aguirre00@usc.edu.co  
 3148765216  

 Estudiantes de Ingeniería en Sistemas  
 Universidad Santiago de Cali  

---

## Estado del proyecto

 Proyecto funcional  
 En mejoras visuales y optimización  

---

## Notas

Este proyecto fue desarrollado como parte de la formación académica, enfocado en el desarrollo de aplicaciones web para monitoreo de sistemas y análisis de datos.
