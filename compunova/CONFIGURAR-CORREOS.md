# CompuNova: cuentas y correos

La tienda ahora puede usar un servidor Node para crear cuentas de clientes, enviar un correo de bienvenida, confirmar suscripciones y recibir consultas. Las contraseñas se guardan como hashes en el servidor y la sesión usa una cookie `HttpOnly`.

## Antes de enviar correos reales

1. Crea una cuenta en Resend y verifica el dominio que usarás como remitente. En modo de prueba, el proveedor puede limitar los destinatarios a direcciones verificadas.
2. En esta carpeta, copia `.env.example` a `.env` y configura `RESEND_API_KEY`, `EMAIL_FROM` y `ADMIN_EMAIL`. Mantén `.env` privado; nunca pongas la clave en `app.js` ni la compartas por chat.
3. Instala Node.js 20 o posterior en el equipo o el servicio donde alojes la tienda.
4. Ejecuta `npm start` desde esta carpeta y abre `http://localhost:3000`.

## Formularios

- Registro: crea la cuenta en el servidor y manda un correo de bienvenida. Si el correo no se pudo enviar, el registro no se completa.
- Inicio de sesión: valida la cuenta guardada en el servidor.
- Contacto: manda una copia de recepción al cliente y la consulta a `ADMIN_EMAIL`.
- Nova Notes: guarda el correo con consentimiento y manda una confirmación.

Los datos de cuentas, suscripciones y consultas se guardan en `data/`. Haz respaldos privados de esa carpeta y no la publiques. Para un sitio con varios servidores o alto tráfico, cambia el almacenamiento JSON por una base de datos administrada.
