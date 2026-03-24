# Backend API (api.ne-nas.ru)

Standalone API для проекта ToolHub. Деплой на отдельный хост (Railway, Render, VPS и т.п.).

## Запуск

```bash
cd backendApi
npm install
npm start
```

Порт по умолчанию: 3003 (переопределяется через `API_PORT`).

## Переменные окружения

| Переменная | Описание |
|------------|----------|
| `API_PORT` | Порт сервера (по умолчанию 3003) |
| `NODE_ENV` | `production` для prod |
| `CORS_ORIGIN` | Разрешённые origins через запятую (например `https://tools.ne-nas.ru`) |
| `JWT_SECRET` | Секрет для JWT |
| `COOKIE_DOMAIN` | Домен для cookies (например `.ne-nas.ru` для tools + api) |
| `COOKIE_SECURE` | `1` для HTTPS |
| `ADMIN_EMAIL` | Email админ-аккаунта |
| `ADMIN_PASSWORD` | Пароль админ-аккаунта |

