# Secret Service — Полная документация

> Централизованная система управления API-ключами и секретами для команд разработчиков.
> Выпускная квалификационная работа (ВКР), УрФУ 2026.

---

## Содержание

1. [Обзор системы](#1-обзор-системы)
2. [Архитектура](#2-архитектура)
3. [База данных и схема](#3-база-данных-и-схема)
4. [Запуск и конфигурация](#4-запуск-и-конфигурация)
5. [Аутентификация и авторизация](#5-аутентификация-и-авторизация)
6. [HTTP API — полный справочник](#6-http-api--полный-справочник)
   - 6.1 [Авторизация (Auth)](#61-авторизация-auth)
   - 6.2 [Пользователи (Users)](#62-пользователи-users)
   - 6.3 [Команды (Teams)](#63-команды-teams)
   - 6.4 [Проекты (Projects)](#64-проекты-projects)
   - 6.5 [Секреты (Secrets)](#65-секреты-secrets)
   - 6.6 [Сервисные аккаунты (Service Accounts)](#66-сервисные-аккаунты-service-accounts)
   - 6.7 [Журнал аудита (Audit)](#67-журнал-аудита-audit)
   - 6.8 [Администрирование (Admin)](#68-администрирование-admin)
   - 6.9 [Системные эндпоинты](#69-системные-эндпоинты)
7. [CLI-клиент](#7-cli-клиент)
8. [Доменная модель](#8-доменная-модель)
9. [Сервисный слой — бизнес-логика](#9-сервисный-слой--бизнес-логика)
10. [Слой хранилища (Storage)](#10-слой-хранилища-storage)
11. [Middleware](#11-middleware)
12. [Криптография](#12-криптография)
13. [JWT-токены](#13-jwt-токены)
14. [Модель прав доступа](#14-модель-прав-доступа)
15. [Аудит и журналирование](#15-аудит-и-журналирование)
16. [Мониторинг (Prometheus)](#16-мониторинг-prometheus)
17. [Миграции базы данных](#17-миграции-базы-данных)

---

## 1. Обзор системы

**Secret Service** — это backend-сервис для безопасного хранения, распространения и управления секретами (API-ключи, токены, пароли, строки подключения) внутри команд разработчиков.

### Ключевые возможности

| Возможность | Описание |
|---|---|
| **Шифрование** | Значения секретов хранятся в зашифрованном виде (AES-256-GCM) |
| **Версионирование** | Каждая ротация создаёт новую версию; поддерживается откат |
| **RBAC** | Роли на уровне проекта: `admin` / `manager` / `developer` |
| **Гранулярный доступ** | Временный доступ к конкретному секрету с TTL |
| **Сервисные аккаунты** | Machine-to-machine аутентификация (CI/CD, деплой-скрипты) |
| **Аудит** | Полный лог всех действий с фильтрацией |
| **Среды** | Разделение секретов по `development` / `staging` / `production` |
| **Теги** | Произвольные теги для группировки секретов |
| **Команды** | Группировка пользователей с массовым назначением на проект |
| **CLI** | Интерактивный CLI-клиент (`ss`) |
| **Мониторинг** | Prometheus-метрики из коробки |
| **Документация** | Swagger UI по адресу `/swagger/` |

---

## 2. Архитектура

```
cmd/
  server/main.go      — точка входа сервера (wire-up)
  cli/main.go         — точка входа CLI-клиента

internal/
  domain/             — доменные модели (чистые Go-структуры)
  dto/                — объекты запросов и ответов (HTTP layer)
  errs/               — централизованные sentinel-ошибки
  crypto/             — AES-256-GCM шифрование
  token/              — JWT (выдача / разбор)
  auth/               — сервис + репозиторий пользователей
  project/            — сервис + репозиторий проектов
  secret/             — сервис + репозиторий секретов
  access/             — сервис + репозиторий грантов доступа
  serviceaccount/     — сервис + репозиторий SA
  team/               — сервис + репозиторий команд
  audit/              — сервис + репозиторий аудита
  admin/              — сервис статистики (admin-only)
  storage/            — реализации репозиториев (PostgreSQL + sqlx)
  handler/            — HTTP-хэндлеры (chi)
  http/               — роутер + регистрация маршрутов
  middleware/         — Auth, Logging, RequestID, Recovery, Metrics, RateLimit

migrations/           — SQL-файлы миграций (001_init.sql ... 009_*)
docs/                 — авто-сгенерированные Swagger JSON/YAML

cmd/cli/
  config.go           — сессия (~/.secret-service/session.json)
  commands/           — cobra-команды (login, logout, secrets, projects, ...)
```

### Поток запроса

```
HTTP Request
    ↓
[Recovery] → [RequestID] → [Logging] → [Metrics]
    ↓
[Auth Middleware] — проверка JWT, извлечение userID
    ↓
Handler (chi router)
    ↓
Service (бизнес-логика, проверки прав)
    ↓
Repository interface
    ↓
storage.* (sqlx + PostgreSQL)
```

Каждый слой зависит только от **интерфейсов** следующего — никаких циклических зависимостей, прямая инъекция зависимостей через конструкторы.

---

## 3. База данных и схема

СУБД: **PostgreSQL 14+**

### Таблицы

#### `users`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| email | TEXT UNIQUE | Электронная почта |
| display_name | TEXT | Отображаемое имя |
| password_hash | TEXT | bcrypt-хэш пароля |
| is_blocked | BOOLEAN | Заблокирован ли пользователь |
| is_admin | BOOLEAN | Является ли глобальным администратором |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

> Первый зарегистрированный пользователь автоматически получает `is_admin = TRUE`.

#### `projects`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| name | TEXT | Название проекта |
| description | TEXT | Описание |
| team_id | TEXT FK→teams | Опциональная привязка к команде |
| created_by | TEXT FK→users | Создатель |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

#### `project_members`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | |
| project_id | TEXT FK→projects | |
| user_id | TEXT FK→users | |
| role | TEXT | `admin` / `manager` / `developer` |
| created_at | TIMESTAMPTZ | |

Уникальный индекс: `(project_id, user_id)`.

#### `teams`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| name | TEXT UNIQUE | Название команды |
| description | TEXT | |
| created_by | TEXT FK→users | |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

#### `team_members`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | |
| team_id | TEXT FK→teams | |
| user_id | TEXT FK→users | |
| role | TEXT | `owner` / `member` |
| created_at | TIMESTAMPTZ | |

#### `project_teams`
| Колонка | Тип | Описание |
|---|---|---|
| project_id | TEXT FK→projects | PK часть |
| team_id | TEXT FK→teams | PK часть |
| assigned_by | TEXT | ID пользователя, назначившего команду |
| assigned_at | TIMESTAMPTZ | |

Записывает факт назначения команды на проект. При назначении все текущие участники команды добавляются в `project_members`.

#### `secrets`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| project_id | TEXT FK→projects | |
| name | TEXT | Уникально в рамках проекта |
| description | TEXT | |
| status | TEXT | `active` / `revoked` |
| environment | TEXT | `development` / `staging` / `production` |
| tags | TEXT[] | Произвольные теги |
| expires_at | TIMESTAMPTZ NULL | TTL секрета |
| created_by | TEXT FK→users | |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

Уникальный индекс: `(project_id, name)`.

#### `secret_versions`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| secret_id | TEXT FK→secrets | |
| version | INT | Номер версии (начиная с 1) |
| encrypted_value | BYTEA | Зашифрованное значение (AES-256-GCM) |
| nonce | BYTEA | Одноразовый nonce для GCM |
| is_current | BOOLEAN | Текущая активная версия |
| created_by | TEXT FK→users | |
| created_at | TIMESTAMPTZ | |

Уникальный индекс: `(secret_id, version)`. Индекс на `(secret_id) WHERE is_current = TRUE`.

#### `access_grants`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| secret_id | TEXT FK→secrets | |
| user_id | TEXT FK→users | |
| granted_by | TEXT FK→users | |
| expires_at | TIMESTAMPTZ NULL | Опциональный TTL гранта |
| created_at | TIMESTAMPTZ | |

Уникальный индекс: `(secret_id, user_id)` — один грант на пару.

#### `service_accounts`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| project_id | TEXT FK→projects | |
| name | TEXT | Уникально в рамках проекта |
| description | TEXT | |
| token_hash | TEXT | bcrypt-хэш токена |
| status | TEXT | `active` / `revoked` |
| created_by | TEXT FK→users | |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

#### `audit_events`
| Колонка | Тип | Описание |
|---|---|---|
| id | TEXT PK | UUID |
| actor_user_id | TEXT FK→users NULL | Кто совершил действие |
| project_id | TEXT FK→projects NULL | В контексте какого проекта |
| secret_id | TEXT FK→secrets NULL | С каким секретом |
| event_type | TEXT | Тип события (см. раздел 15) |
| metadata | JSONB | Дополнительные данные |
| created_at | TIMESTAMPTZ | |

Составные индексы: `(project_id, created_at DESC)`, `(secret_id, created_at DESC)`.

#### `schema_migrations`
Служебная таблица для отслеживания применённых SQL-миграций.

---

## 4. Запуск и конфигурация

### Переменные окружения

| Переменная | Обязательная | Описание | Пример |
|---|---|---|---|
| `DATABASE_URL` | ✅ | Строка подключения к PostgreSQL | `postgres://user:pass@localhost:5432/secrets` |
| `AES_KEY_HEX` | ✅ | 32-байтовый ключ шифрования в hex (64 символа) | `a1b2c3...` (64 hex-символа) |
| `JWT_SECRET` | ✅ | Секрет для подписи JWT | `supersecret` |
| `PORT` | ❌ | Порт HTTP-сервера (по умолчанию `8080`) | `8080` |
| `LOG_LEVEL` | ❌ | Уровень логирования: `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` |

### Запуск сервера

```bash
export DATABASE_URL="postgres://user:pass@localhost:5432/secrets?sslmode=disable"
export AES_KEY_HEX="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
export JWT_SECRET="my-secret-key"
go run ./cmd/server
```

При запуске автоматически:
1. Проверяется наличие и корректность всех обязательных переменных
2. Выполняются все непримененные SQL-миграции
3. Запускается HTTP-сервер с graceful shutdown (ожидает SIGINT / SIGTERM, таймаут 15 с)

### Запуск CLI

```bash
go run ./cmd/cli --help
# или после сборки:
./ss --help
```

---

## 5. Аутентификация и авторизация

### Пользовательские JWT-токены

- Алгоритм: **HS256**
- TTL: **24 часа**
- Payload: `user_id`, `sub: "user"`, `is_admin`
- Передаются в заголовке: `Authorization: Bearer <token>`

### Токены сервисных аккаунтов

- Алгоритм: **HS256**
- TTL: **1 час** (намеренно короткий)
- Payload: `user_id` (= ID сервис-аккаунта), `sub: "service_account"`, `project_id`
- Передаются так же: `Authorization: Bearer <token>`

### Схема проверки доступа к секрету

```
Запрос GET /secrets/{id}/value
    ↓
Секрет активен? (status = 'active') и не истёк? (expires_at > NOW())
    ↓
Пользователь — участник проекта?
  → Да: доступ разрешён
  → Нет: есть активный access_grant для этого пользователя?
      → Да + grant не истёк: доступ разрешён
      → Нет: 403 Forbidden, событие audit secret_read_denied
```

### Глобальная роль `is_admin`

Глобальные администраторы могут:
- Просматривать список всех пользователей
- Блокировать / разблокировать пользователей
- Просматривать глобальный аудит-лог
- Получать статистику платформы (`GET /admin/stats`)

---

## 6. HTTP API — полный справочник

Базовый URL: `http://localhost:8080`
Swagger UI: `http://localhost:8080/swagger/`

Все защищённые эндпоинты требуют заголовок:
```
Authorization: Bearer <jwt_token>
```

---

### 6.1 Авторизация (Auth)

#### `POST /api/v1/auth/register` — Регистрация пользователя

Публичный. Ограничен rate limiter'ом (5 req/s).

**Тело запроса:**
```json
{
  "email": "alice@example.com",
  "password": "strongpassword123"
}
```

**Ответ `201`:**
```json
{
  "id": "uuid",
  "email": "alice@example.com",
  "display_name": "",
  "is_blocked": false,
  "is_admin": true,
  "created_at": "2026-03-18T10:00:00Z",
  "updated_at": "2026-03-18T10:00:00Z"
}
```
> Первый зарегистрированный пользователь получает `is_admin: true`.

**Ошибки:** `400` — пустой email/пароль, `409` — email уже занят.

---

#### `POST /api/v1/auth/login` — Вход в систему

Публичный. Ограничен rate limiter'ом.

**Тело запроса:**
```json
{
  "email": "alice@example.com",
  "password": "strongpassword123"
}
```

**Ответ `200`:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Ошибки:** `401` — неверные учётные данные, `403` — пользователь заблокирован.

---

#### `GET /api/v1/auth/me` — Информация о текущем пользователе

🔒 Требует JWT.

**Ответ `200`:** объект `User`.

---

#### `PATCH /api/v1/auth/me` — Обновить отображаемое имя

🔒 Требует JWT.

**Тело запроса:**
```json
{
  "display_name": "Alice Smith"
}
```

**Ответ `200`:** обновлённый объект `User`.

---

### 6.2 Пользователи (Users)

#### `GET /api/v1/users` — Список всех пользователей

🔒 Только `is_admin = true`.

**Параметры запроса:** `?limit=20&offset=0`

**Ответ `200`:** массив объектов `User`.

---

#### `POST /api/v1/users/{userID}/block` — Заблокировать пользователя

🔒 Только `is_admin`. Нельзя заблокировать себя.

**Ответ `204`** — нет тела.

---

#### `POST /api/v1/users/{userID}/unblock` — Разблокировать пользователя

🔒 Только `is_admin`. Нельзя разблокировать себя.

**Ответ `204`** — нет тела.

---

### 6.3 Команды (Teams)

Команда — это именованная группа пользователей. Команду можно одним действием назначить на проект, добавив всех участников как members.

#### `POST /api/v1/teams` — Создать команду

🔒 Требует JWT.

**Тело:**
```json
{
  "name": "Backend Team",
  "description": "Команда backend-разработчиков"
}
```

**Ответ `201`:** объект `Team`. Создатель автоматически получает роль `owner`.

---

#### `GET /api/v1/teams` — Список команд текущего пользователя

🔒 Требует JWT.

**Ответ `200`:** массив объектов `Team`.

---

#### `POST /api/v1/teams/{teamID}/members` — Добавить участника в команду

🔒 Только `owner` команды.

**Тело:**
```json
{
  "user_id": "uuid",
  "role": "member"
}
```
Допустимые роли: `owner`, `member`.

**Ответ `204`**.

---

#### `DELETE /api/v1/teams/{teamID}/members/{userID}` — Удалить участника из команды

🔒 Только `owner` команды.

**Ответ `204`**.

---

#### `GET /api/v1/teams/{teamID}/members` — Список участников команды

🔒 Требует JWT.

**Ответ `200`:** массив объектов `TeamMember`.

---

### 6.4 Проекты (Projects)

Проект — основная единица разграничения секретов. Каждый секрет принадлежит одному проекту.

#### `POST /api/v1/projects` — Создать проект

🔒 Требует JWT.

**Тело:**
```json
{
  "name": "payment-service",
  "description": "Платёжный микросервис"
}
```

**Ответ `201`:** объект `Project`. Создатель автоматически становится `admin`.

---

#### `GET /api/v1/projects` — Список проектов текущего пользователя

🔒 Требует JWT.

**Параметры:** `?limit=20&offset=0`

**Ответ `200`:** массив объектов `Project`.

---

#### `GET /api/v1/projects/{projectID}` — Получить проект по ID

🔒 Только участники проекта.

**Ответ `200`:** объект `Project`.

---

#### `GET /api/v1/projects/{projectID}/members` — Список участников проекта

🔒 Любой участник проекта.

**Параметры:** `?limit=20&offset=0`

**Ответ `200`:** массив объектов `ProjectMember`.

---

#### `POST /api/v1/projects/{projectID}/members` — Добавить участника

🔒 Только `admin` проекта.

**Тело:**
```json
{
  "user_id": "uuid",
  "role": "developer"
}
```
Допустимые роли: `admin`, `manager`, `developer`.

**Ответ `204`**. Если пользователь уже является участником — роль обновляется (upsert).

---

#### `PATCH /api/v1/projects/{projectID}/members/{userID}` — Изменить роль участника

🔒 Только `admin` проекта.

**Тело:**
```json
{
  "role": "manager"
}
```

**Ответ `204`**.

---

#### `DELETE /api/v1/projects/{projectID}/members/{userID}` — Удалить участника

🔒 Только `admin` проекта. Нельзя удалить себя.

**Ответ `204`**.

---

#### `POST /api/v1/projects/{projectID}/teams` — Назначить команду на проект

🔒 Только `admin` проекта.

Массово добавляет всех текущих участников команды в проект с указанной ролью. Записывает связь в `project_teams`.

**Тело:**
```json
{
  "team_id": "uuid",
  "role": "developer"
}
```
`role` — необязательный, по умолчанию `developer`.

**Ответ `204`**.

---

#### `DELETE /api/v1/projects/{projectID}/teams/{teamID}` — Снять команду с проекта

🔒 Только `admin` проекта.

Удаляет запись из `project_teams`. **Не удаляет** участников из `project_members` — пользователи остаются в проекте.

**Ответ `204`**.

---

#### `GET /api/v1/projects/{projectID}/teams` — Список назначенных команд

🔒 Любой участник проекта.

**Ответ `200`:** массив объектов `ProjectTeam`.

```json
[
  {
    "project_id": "uuid",
    "team_id": "uuid",
    "assigned_by": "uuid",
    "assigned_at": "2026-03-18T10:00:00Z"
  }
]
```

---

### 6.5 Секреты (Secrets)

Секрет — именованная зашифрованная запись внутри проекта. Значение никогда не хранится в открытом виде.

#### `POST /api/v1/projects/{projectID}/secrets` — Создать секрет

🔒 Только `admin` / `manager` проекта.

**Тело:**
```json
{
  "name": "STRIPE_API_KEY",
  "description": "Stripe payment secret key",
  "value": "sk_live_...",
  "environment": "production",
  "tags": ["payment", "external"],
  "expires_at": "2026-12-31T23:59:59Z"
}
```

| Поле | Обязательное | Описание |
|---|---|---|
| `name` | ✅ | Уникально в рамках проекта |
| `value` | ✅ | Секретное значение (шифруется немедленно) |
| `description` | ❌ | Описание |
| `environment` | ❌ | `development` / `staging` / `production` (умолч. `production`) |
| `tags` | ❌ | Массив строк-тегов |
| `expires_at` | ❌ | Дата истечения в ISO 8601 |

**Ответ `201`:** объект `Secret` (без значения).

---

#### `GET /api/v1/projects/{projectID}/secrets` — Список секретов проекта

🔒 Любой участник проекта.

**Параметры фильтрации:**

| Параметр | Описание | Пример |
|---|---|---|
| `?environment=` | Фильтр по среде | `?environment=production` |
| `?status=` | Фильтр по статусу | `?status=active` |
| `?name=` | Поиск по имени (ILIKE, без учёта регистра) | `?name=stripe` |
| `?tag=` | Фильтр по тегу (можно несколько; секрет должен содержать ВСЕ теги) | `?tag=payment&tag=external` |
| `?limit=` | Размер страницы (умолч. 20, макс. 200) | `?limit=50` |
| `?offset=` | Смещение | `?offset=20` |

**Ответ `200`:** массив объектов `Secret`.

---

#### `GET /api/v1/secrets/{secretID}/value` — Получить значение секрета

🔒 Участник проекта **или** пользователь с активным `access_grant`.

Расшифровывает и возвращает актуальное значение. Регистрирует событие `secret_read` в аудите.

**Ответ `200`:**
```json
{
  "secret_id": "uuid",
  "value": "sk_live_..."
}
```

**Ошибки:** `403` — нет доступа (фиксируется как `secret_read_denied`), `410` — секрет отозван или истёк.

---

#### `POST /api/v1/secrets/{secretID}/revoke` — Отозвать секрет

🔒 Только `admin` / `manager` проекта.

Переводит секрет в статус `revoked`. После этого его значение нельзя получить.

**Ответ `204`**.

---

#### `POST /api/v1/secrets/{secretID}/rotate` — Ротация значения секрета

🔒 Только `admin` / `manager` проекта.

Создаёт новую версию секрета. Старая версия сохраняется в истории (можно откатить).

**Тело:**
```json
{
  "value": "sk_live_newvalue..."
}
```

**Ответ `204`**.

---

#### `GET /api/v1/secrets/{secretID}/versions` — История версий

🔒 Любой участник проекта.

Возвращает метаданные версий **без** зашифрованных значений.

**Ответ `200`:**
```json
[
  {
    "id": "uuid",
    "secret_id": "uuid",
    "version": 3,
    "is_current": true,
    "created_by": "uuid",
    "created_at": "2026-03-18T10:00:00Z"
  },
  {
    "version": 2,
    "is_current": false,
    ...
  }
]
```

---

#### `POST /api/v1/secrets/{secretID}/rollback` — Откат на предыдущую версию

🔒 Только `admin` / `manager` проекта.

**Тело:**
```json
{
  "version": 2
}
```

Атомарно переключает текущую версию на указанную (одним SQL-запросом).

**Ответ `204`**.

---

#### `GET /api/v1/projects/{projectID}/secrets/expiring` — Секреты с истекающим сроком

🔒 Любой участник проекта.

**Параметры:** `?days=7` (по умолчанию 7, любое положительное число).

Возвращает активные секреты, у которых `expires_at` наступит в течение следующих N дней, отсортированные по возрастанию `expires_at`.

**Ответ `200`:** массив объектов `Secret`.

---

#### `GET /api/v1/projects/{projectID}/secrets/{secretID}/grants` — Список грантов доступа

🔒 Только `admin` / `manager` проекта.

**Ответ `200`:** массив объектов `AccessGrant`.

---

#### `POST /api/v1/projects/{projectID}/secrets/{secretID}/grants` — Выдать доступ

🔒 Только `admin` / `manager` проекта.

**Тело:**
```json
{
  "user_id": "uuid",
  "expires_at": "2026-04-01T00:00:00Z"
}
```
`expires_at` — необязательный. Если указан — грант истечёт автоматически.

**Ответ `204`**. Если грант уже существует — обновляется (upsert).

---

#### `DELETE /api/v1/projects/{projectID}/secrets/{secretID}/grants/{userID}` — Отозвать доступ

🔒 Только `admin` / `manager` проекта.

**Ответ `204`**.

---

### 6.6 Сервисные аккаунты (Service Accounts)

Сервисные аккаунты используются для machine-to-machine аутентификации (CI/CD, деплой-скрипты). Токен показывается **один раз** при создании.

#### `POST /api/v1/projects/{projectID}/service-accounts` — Создать SA

🔒 Только `admin` / `manager` проекта.

**Тело:**
```json
{
  "name": "github-actions-deployer",
  "description": "Деплой из GitHub Actions"
}
```

**Ответ `201`:**
```json
{
  "id": "uuid",
  "project_id": "uuid",
  "name": "github-actions-deployer",
  "description": "...",
  "token": "sa_a1b2c3d4e5...",
  "warning": "Save this token — it is shown only once"
}
```

> Токен хранится как bcrypt-хэш. Сохраните его немедленно.

---

#### `POST /api/v1/auth/service-login` — Аутентификация SA

Публичный. Ограничен rate limiter'ом.

**Тело:**
```json
{
  "service_account_id": "uuid",
  "token": "sa_a1b2c3d4e5..."
}
```

**Ответ `200`:**
```json
{
  "access_token": "eyJ..."
}
```

JWT-токен SA действует **1 час** (короткий TTL для безопасности). Токен содержит `project_id`.

---

#### `GET /api/v1/projects/{projectID}/service-accounts` — Список SA проекта

🔒 Любой участник проекта.

**Ответ `200`:** массив объектов `ServiceAccount` (без `token_hash`).

---

#### `POST /api/v1/service-accounts/{saID}/revoke` — Отозвать SA

🔒 Только `admin` / `manager` проекта.

**Ответ `204`**.

---

### 6.7 Журнал аудита (Audit)

#### `GET /api/v1/projects/{projectID}/audit/events` — Аудит проекта

🔒 Только участники проекта.

**Параметры фильтрации:**

| Параметр | Описание |
|---|---|
| `?event_type=` | Тип события (например, `secret_read`) |
| `?actor_user_id=` | Кто совершил действие |
| `?secret_id=` | По конкретному секрету |
| `?from=` | С даты (ISO 8601) |
| `?to=` | По дату (ISO 8601) |
| `?limit=` | Количество (1–500, умолч. 100) |

**Ответ `200`:** массив объектов `AuditEvent`.

---

#### `GET /api/v1/audit/events` — Глобальный аудит-лог

🔒 Только `is_admin`.

Поддерживает те же параметры фильтрации. Возвращает события по всей платформе.

---

### 6.8 Администрирование (Admin)

#### `GET /api/v1/admin/stats` — Статистика платформы

🔒 Только `is_admin`.

Выполняет один агрегирующий SQL-запрос и возвращает сводку по всей платформе.

**Ответ `200`:**
```json
{
  "total_users": 42,
  "total_projects": 15,
  "total_secrets_active": 230,
  "total_secrets_revoked": 18,
  "total_service_accounts": 9,
  "audit_events_last_24h": 87,
  "expiring_secrets_7d": 3
}
```

| Поле | Описание |
|---|---|
| `total_users` | Все пользователи |
| `total_projects` | Все проекты |
| `total_secrets_active` | Активные секреты |
| `total_secrets_revoked` | Отозванные секреты |
| `total_service_accounts` | Активные сервисные аккаунты |
| `audit_events_last_24h` | Количество событий за последние 24 ч |
| `expiring_secrets_7d` | Активные секреты с истечением в ближайшие 7 дней |

---

### 6.9 Системные эндпоинты

#### `GET /health` — Проверка состояния

Публичный. Пингует БД с таймаутом 2 секунды.

**Ответ `200`:**
```json
{"status": "ok", "db": "reachable"}
```

**Ответ `503`** (если БД недоступна):
```json
{"status": "unavailable", "db": "unreachable"}
```

---

#### `GET /metrics` — Prometheus-метрики

Публичный. Возвращает метрики в формате Prometheus text exposition.

---

#### `GET /swagger/*` — Swagger UI

Публичный. Интерактивная документация API.

---

## 7. CLI-клиент

### Установка и сборка

```bash
go build -o ss ./cmd/cli
./ss --help
```

### Конфигурация сессии

Сессия хранится в файле `~/.secret-service/session.json` с правами `0600`:
```json
{
  "token": "eyJ...",
  "server_url": "http://localhost:8080"
}
```

### Доступные команды

#### `ss login` — Вход

Запрашивает email интерактивно, пароль вводится без эха (скрытый ввод через `golang.org/x/term`). Сохраняет JWT-токен в сессию.

#### `ss logout` — Выход

Удаляет локальный файл сессии.

#### `ss whoami` — Текущий пользователь

Выводит информацию о вошедшем пользователе.

#### `ss projects` — Управление проектами

```
ss projects list              — список проектов
ss projects create <name>     — создать проект
ss projects members <id>      — участники проекта
```

#### `ss secrets` — Управление секретами

```
ss secrets list <project-id>              — список секретов
ss secrets create <project-id>            — создать секрет (значение вводится скрыто)
ss secrets get <secret-id>               — получить значение
ss secrets rotate <secret-id>            — ротация (новое значение вводится скрыто)
```

#### `ss run` — Запуск скрипта с секретами

Загружает секреты проекта как переменные окружения и выполняет команду:
```bash
ss run <project-id> -- npm run deploy
```

---

## 8. Доменная модель

Ядро системы — пакет `internal/domain`. Содержит только чистые Go-структуры без зависимостей от БД или HTTP.

### Иерархия сущностей

```
User (глобальный)
  └── ProjectMember → Project
                         ├── Secret
                         │     ├── SecretVersion (история)
                         │     └── AccessGrant (гранулярный доступ)
                         ├── ServiceAccount
                         └── ProjectTeam → Team
                                             └── TeamMember → User
```

### Роли

**Роли в проекте (`ProjectRole`):**
- `admin` — полный контроль: управление участниками, секретами, командами
- `manager` — управление секретами (создание, ротация, отзыв, гранты)
- `developer` — чтение секретов при наличии гранта

**Роли в команде (`TeamRole`):**
- `owner` — управление составом команды
- `member` — обычный участник

**Глобальные роли (`is_admin`):**
- Управление пользователями, глобальный аудит, статистика

---

## 9. Сервисный слой — бизнес-логика

Каждый сервис получает зависимости через интерфейсы (репозитории, вспомогательные сервисы) и содержит всю бизнес-логику. Хэндлеры вызывают только методы сервисов.

### `auth.Service`

```
CreateUser(email, password)
  → хэширует пароль (bcrypt)
  → первый пользователь → is_admin = true
  → пишет аудит: user_registered

Login(email, password)
  → ищет пользователя по email
  → сравнивает bcrypt хэш
  → заблокирован? → 403
  → генерирует JWT (24 ч)
  → пишет аудит: user_logged_in

BlockUser(actorID, targetID)
  → actor должен быть is_admin
  → actor != target (нельзя заблокировать себя)
  → пишет аудит: user_blocked

UnblockUser(actorID, targetID)
  → actor должен быть is_admin
  → actor != target
  → пишет аудит: user_unblocked
```

### `project.Service`

```
CreateProject(actorID, name, desc)
  → создаёт Project
  → добавляет создателя как admin в project_members
  → пишет аудит: project_created

AssignTeam(actorID, projectID, teamID, role)
  → actor должен быть admin проекта
  → записывает project_teams
  → получает всех участников команды
  → для каждого: AddMember(..., role) — upsert
  → пишет аудит: project_team_assigned

RemoveMember(actorID, projectID, targetID)
  → actor должен быть admin
  → actor != target (нельзя удалить себя)
```

### `secret.Service`

```
CreateSecret(actorID, projectID, name, ..., tags, expiresAt)
  → actor должен быть admin / manager
  → шифрует value → AES-256-GCM
  → создаёт Secret + SecretVersion (version=1, is_current=true)
  → пишет аудит: secret_created

GetSecretValue(actorID, secretID)
  → статус active? expires_at > NOW()?
  → CanReadSecret: member проекта ИЛИ active access_grant
  → нет доступа → аудит: secret_read_denied
  → расшифровывает текущую версию
  → пишет аудит: secret_read

RotateSecret(actorID, secretID, newValue)
  → actor: admin / manager
  → сбрасывает is_current у всех версий
  → создаёт новую версию (n+1, is_current=true)
  → пишет аудит: secret_rotated

RollbackSecret(actorID, secretID, version)
  → actor: admin / manager
  → проверяет, что версия существует
  → атомарный UPDATE: is_current = (version = $target)
  → пишет аудит: secret_rolled_back

ListExpiringSecrets(actorID, projectID, days)
  → actor: любой участник
  → SQL: WHERE expires_at > NOW() AND expires_at <= NOW() + (days * 1 day)
```

### `access.Service`

```
CanReadSecret(projectID, secretID, userID)
  → участник проекта? → true
  → активный access_grant без истечения или expires_at > NOW()? → true
  → иначе false

GrantAccess(actorID, projectID, secretID, userID, expiresAt)
  → actor: admin / manager проекта
  → upsert access_grant
  → аудит: access_granted

ListGrants(actorID, projectID, secretID)
  → actor: admin / manager
```

---

## 10. Слой хранилища (Storage)

Все репозитории находятся в `internal/storage/`, используют `github.com/jmoiron/sqlx`.

### Паттерны

**Динамический WHERE:**
```go
// Пример из ListSecretsByProject
args := []interface{}{projectID}
where := "project_id = $1"
idx := 2

if f.Environment != nil {
    where += fmt.Sprintf(" AND environment = $%d", idx)
    args = append(args, *f.Environment); idx++
}
if len(f.Tags) > 0 {
    where += fmt.Sprintf(" AND tags @> $%d", idx)
    args = append(args, pq.StringArray(f.Tags)); idx++
}
args = append(args, limit, offset)
q := fmt.Sprintf(`SELECT * FROM secrets WHERE %s LIMIT $%d OFFSET $%d`, where, idx, idx+1)
```

**Обработка конфликтов:**
```go
var pqErr *pq.Error
if errors.As(err, &pqErr) && pqErr.Code == "23505" {
    return errs.ErrConflict
}
```

**Not Found:**
```go
func mapNotFound(err error) error {
    if errors.Is(err, sql.ErrNoRows) {
        return errs.ErrNotFound
    }
    return err
}
```

### Репозитории

| Структура | Файл | Ключевые методы |
|---|---|---|
| `UserRepo` | `user_repo.go` | Create, GetByID, GetByEmail, Block, Unblock, ListAll, UpdateDisplayName |
| `ProjectRepo` | `project_repo.go` | CreateProject, GetProjectByID, AddMember, RemoveMember, UpdateMemberRole, ListMembers, AssignTeam, UnassignTeam, ListProjectTeams |
| `SecretRepo` | `secret_repo.go` | CreateSecret, GetSecretByID, ListSecretsByProject, UpdateSecretStatus, CreateVersion, GetCurrentVersion, ListVersions, SetCurrentVersion, ListExpiringSecrets |
| `AccessGrantRepo` | `access_audit_repo.go` | CreateGrant, DeleteGrant, GetGrant, ListGrants |
| `AuditRepo` | `access_audit_repo.go` | CreateEvent, ListProjectEvents, ListSecretEvents, ListEvents |
| `ServiceAccountRepo` | `sa_repo.go` | Create, GetByID, GetByProjectID, UpdateStatus, ListByProject |
| `TeamRepo` | `team_repo.go` | CreateTeam, GetByID, ListByUser, AddMember, RemoveMember, GetMember, ListMembers |
| `StatsRepo` | `stats_repo.go` | GetStats (один агрегирующий запрос) |

---

## 11. Middleware

Порядок применения в роутере: **Recovery → RequestID → Logging → Metrics**

### Recovery

Перехватывает паники в хэндлерах. Логирует через `slog.ErrorContext` с полями `error`, `request_id`, `path`. Возвращает `500 Internal Server Error`.

### RequestID

Читает заголовок `X-Request-ID`. Если отсутствует — генерирует новый UUID. Сохраняет в контекст, устанавливает заголовок ответа. Используется во всех последующих логах.

### Logging (slog)

Структурированное JSON-логирование каждого запроса:
```json
{
  "time": "2026-03-18T10:00:00Z",
  "level": "INFO",
  "msg": "request",
  "method": "GET",
  "path": "/api/v1/secrets/uuid/value",
  "status": 200,
  "duration_ms": 12,
  "request_id": "550e8400-...",
  "remote_addr": "192.168.1.1:54321"
}
```

### Metrics

Собирает Prometheus-метрики для каждого запроса:
- `http_requests_total` (counter) — по `method`, `path`, `status`
- `http_request_duration_seconds` (histogram) — по `method`, `path`

### Auth

Извлекает JWT из `Authorization: Bearer <token>`. При валидном токене кладёт `userID` в контекст (`UserIDKey`). При невалидном — `401 Unauthorized`.

### RateLimiter

Per-IP rate limiting с token bucket алгоритмом (`golang.org/x/time/rate`). Применяется только на публичных эндпоинтах `/auth/register`, `/auth/login`, `/auth/service-login`.

- **Лимит:** 5 запросов/сек, burst 10
- **Очистка:** каждые 5 минут удаляет записи для IP, не делавших запросов > 1 минуты
- При превышении: `429 Too Many Requests`

---

## 12. Криптография

### Алгоритм: AES-256-GCM

Файл: `internal/crypto/aesgcm.go`

```go
type AESGCMService struct {
    key []byte  // ровно 32 байта (AES-256)
}

// Encrypt: генерирует случайный 12-байтовый nonce,
// шифрует plainText, возвращает (cipherText, nonce)
func (s *AESGCMService) Encrypt(plainText []byte) ([]byte, []byte, error)

// Decrypt: воссоздаёт GCM с сохранённым nonce,
// расшифровывает и проверяет аутентификационный тег
func (s *AESGCMService) Decrypt(cipherText, nonce []byte) ([]byte, error)
```

**Особенности:**
- Каждая версия секрета имеет уникальный nonce — повторное использование ключа+nonce невозможно
- GCM обеспечивает аутентификацию (AEAD) — подмена шифртекста обнаруживается
- `AES_KEY_HEX` проверяется при старте: ровно 64 hex-символа (32 байта)
- Значения версий никогда не возвращаются в API (только расшифрованный plaintext через `GetSecretValue`)

---

## 13. JWT-токены

Файл: `internal/token/jwt.go`

### Claims

```go
type Claims struct {
    UserID    string
    Subject   string  // "user" или "service_account"
    IsAdmin   bool
    ProjectID string  // только для SA, указывает привязанный проект
    jwt.RegisteredClaims
}
```

### Методы

| Метод | Описание |
|---|---|
| `GenerateWithClaims(userID, isAdmin)` | Создаёт пользовательский JWT (24 ч) |
| `GenerateForSA(saID, projectID)` | Создаёт SA JWT (1 ч) |
| `Parse(tokenStr)` | Извлекает только userID |
| `ParseClaims(tokenStr)` | Извлекает полный объект Claims |

---

## 14. Модель прав доступа

### Матрица прав

| Действие | `developer` | `manager` | `admin` | `is_admin` (глобал.) |
|---|---|---|---|---|
| Просмотр метаданных секрета | ✅ | ✅ | ✅ | — |
| Чтение значения секрета | 🔑* | ✅ | ✅ | — |
| Создание / ротация / откат секрета | ❌ | ✅ | ✅ | — |
| Отзыв секрета | ❌ | ✅ | ✅ | — |
| Выдача / отзыв гранта доступа | ❌ | ✅ | ✅ | — |
| Просмотр грантов | ❌ | ✅ | ✅ | — |
| Управление участниками проекта | ❌ | ❌ | ✅ | — |
| Назначение/снятие команды | ❌ | ❌ | ✅ | — |
| Список пользователей | ❌ | ❌ | ❌ | ✅ |
| Блокировка пользователей | ❌ | ❌ | ❌ | ✅ |
| Глобальный аудит-лог | ❌ | ❌ | ❌ | ✅ |
| Статистика платформы | ❌ | ❌ | ❌ | ✅ |

> 🔑* `developer` может читать секрет, если для него выдан активный `access_grant`.

---

## 15. Аудит и журналирование

### Типы событий аудита

| `event_type` | Когда генерируется |
|---|---|
| `user_registered` | Регистрация пользователя |
| `user_logged_in` | Успешный вход |
| `user_blocked` | Блокировка пользователя |
| `user_unblocked` | Разблокировка пользователя |
| `project_created` | Создание проекта |
| `project_member_added` | Добавление участника в проект |
| `project_team_assigned` | Назначение команды на проект |
| `secret_created` | Создание секрета |
| `secret_read` | Успешное чтение значения секрета |
| `secret_read_denied` | Отказ в доступе к секрету |
| `secret_revoked` | Отзыв секрета |
| `secret_rotated` | Ротация значения |
| `secret_rolled_back` | Откат на предыдущую версию |
| `access_granted` | Выдача гранта доступа |
| `access_revoked` | Отзыв гранта доступа |
| `team_created` | Создание команды |

### Структурированные логи (slog)

Сервер пишет JSON-логи в stdout. Уровень управляется переменной `LOG_LEVEL`.

Пример лога паники:
```json
{
  "time": "2026-03-18T10:00:00Z",
  "level": "ERROR",
  "msg": "panic recovered",
  "error": "runtime error: index out of range",
  "request_id": "550e8400-...",
  "path": "/api/v1/secrets/uuid/value"
}
```

---

## 16. Мониторинг (Prometheus)

Доступно на `GET /metrics`.

### Метрики

#### `http_requests_total` (Counter)
Общее количество HTTP-запросов.

**Labels:** `method`, `path`, `status`

```promql
# RPS по методу
rate(http_requests_total[1m])

# Количество ошибок 5xx
sum(http_requests_total{status=~"5.."})
```

#### `http_request_duration_seconds` (Histogram)
Время обработки запросов.

**Labels:** `method`, `path`

**Buckets:** 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s

```promql
# Медиана latency
histogram_quantile(0.5, rate(http_request_duration_seconds_bucket[5m]))

# 99-й перцентиль
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))
```

---

## 17. Миграции базы данных

Миграции применяются **автоматически при старте сервера** через функцию `storage.RunMigrations()`.

Состояние отслеживается в таблице `schema_migrations`. Уже применённые файлы пропускаются.

| Файл | Содержание |
|---|---|
| `001_init.sql` | Базовые таблицы: users, projects, project_members, secrets, secret_versions, access_grants, audit_events |
| `002_service_accounts.sql` | Таблица service_accounts |
| `003_user_fields.sql` | Поля display_name, is_blocked в users |
| `004_teams.sql` | Таблицы teams, team_members; поле team_id в projects |
| `005_user_admin.sql` | Поле is_admin в users |
| `006_secret_ttl.sql` | Поле expires_at в secrets |
| `007_secret_environment.sql` | Поле environment в secrets |
| `008_secret_tags.sql` | Поле tags (TEXT[]) в secrets |
| `009_project_teams.sql` | Таблица project_teams |

Для добавления новой миграции: создайте файл `0NN_description.sql` в директории `migrations/`. При следующем старте он будет применён автоматически.

---

*Документация актуальна на дату: март 2026.*
