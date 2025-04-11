# Custom-Shellcode_x86

---

# 🔥 Custom Reverse Shell Shellcode Generator

Este proyecto genera *shellcode personalizado en ASM x86* para establecer una **reverse shell en Windows**, con IP y puerto definidos por el usuario. El shellcode se ensambla dinámicamente utilizando la librería [Keystone Engine](https://www.keystone-engine.org/), lo que permite generar payloads para pruebas de pentesting.

---

## ⚙️ Características

- 🔧 Generación dinámica de shellcode en tiempo de ejecución
- 🧠 Resolución de funciones usando hashing y parsing de la Export Address Table
- 📦 Uso de llamadas directas a funciones de WinAPI (`WSAStartup`, `WSASocketA`, `WSAConnect`, `CreateProcessA`, etc.)
- 💀 Payload ejecuta `cmd.exe` remotamente tras la conexión
- ✅ Compatible con arquitectura **x86 (32 bits)**

---

## 📥 Requisitos

- Python 3.6+
- [Keystone Engine](https://www.keystone-engine.org/)
- Numpy

Instalación de dependencias:

```bash
pip install keystone-engine numpy
```

---

## 🧠 ¿Cómo funciona?

1. **Hashing de funciones WinAPI**: El código genera hashes personalizados a partir de nombres de funciones (como `LoadLibraryA` o `CreateProcessA`) usando operaciones `ROR` para evitar strings en claro.
2. **Búsqueda dinámica de funciones**: Se busca `kernel32.dll` y `ws2_32.dll` en tiempo de ejecución, y se resuelven direcciones mediante parsing manual de la EAT (Export Address Table).
3. **Construcción del shellcode**: Se genera código ensamblador personalizado, y se ensambla usando Keystone en formato de bytes (`\x..`).
4. **Ejemplo de ejecución opcional**: Se incluye una sección comentada para asignar memoria y ejecutar el shellcode usando la API de Windows.

---

## 🚀 Uso

```bash
python3 custom_shellcode.py <IP> <PORT>
```

Ejemplo:

```bash
python3 custom_shellcode.py 192.168.1.100 4444
```

Esto imprimirá el shellcode ensamblado:

```python
shellcode = b"\x31\xc9\x64\x8b\x71\x30..." 
```

---

## 🧪 Testeo (opcional)

**⚠️ Atención: esta sección ejecuta shellcode arbitrario. Úsalo solo en entornos controlados.**

Puedes descomentar la sección inferior del script para:

- Asignar memoria en el proceso actual
- Copiar el shellcode
- Crear un hilo de ejecución con `CreateThread`

---

## 🛡️ Advertencia

> **Este proyecto tiene fines únicamente educativos y de investigación en seguridad.**
>
> El uso de este código contra sistemas sin autorización puede constituir una violación legal. El autor no se hace responsable del mal uso del software.

---

## 🧑‍💻 Autor

- 🧠 **David Fernandez Hernandez (ZEROxYakuza)**
- 🛠️ Proyecto para fines de aprendizaje en seguridad ofensiva y desarrollo de exploits
