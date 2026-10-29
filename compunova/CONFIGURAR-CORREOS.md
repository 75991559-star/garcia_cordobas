# CompuNova: envío de correos por SMTP

La tienda usa únicamente SMTP. No usa Resend ni una clave API. Hace falta una cuenta de correo que permita envío SMTP y sus credenciales. El servidor manda correos de bienvenida, confirmaciones de formularios, consultas y pedidos de demostración al cliente y a `ADMIN_EMAIL`.

## Configuración

1. En `.env`, define `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER` y `SMTP_PASS` según el proveedor de tu correo. `SMTP_USER` suele ser la dirección completa y `SMTP_PASS` debe ser la contraseña SMTP o contraseña de aplicación que indique el proveedor.
2. Configura `EMAIL_FROM` con una dirección autorizada por ese proveedor y `ADMIN_EMAIL` con el correo que recibirá los pedidos.
3. Ejecuta `pnpm install` y luego `pnpm start` desde esta carpeta. Tras cambiar `.env`, reinicia el servidor.

No envíes contraseñas por el chat. En Gmail, el servidor es `smtp.gmail.com`; Google requiere verificación en dos pasos para crear contraseñas de aplicación. Consulta [la ayuda oficial de Google](https://support.google.com/accounts/answer/185833?hl=es) y [la configuración SMTP](https://support.google.com/mail/answer/7104828?hl=es). Otros proveedores tienen su propio servidor y requisitos.

## Compra de demostración

La página `pago.html` simula el pago: no cobra dinero ni pide números de tarjeta. Al confirmar, registra el pedido en `data/orders.json` e intenta enviar una confirmación real al cliente y un aviso a `ADMIN_EMAIL`.

Los perfiles, suscripciones, consultas y pedidos se guardan en archivos dentro de `data/`. Mantén esa carpeta privada y haz respaldos.
