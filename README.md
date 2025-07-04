# Medods Auth App (Test Task)

Привет! Это мой сервис аутентификации на Go с PostgreSQL и Redis — тестовое задание на позицию Junior Backend Developer.

---

## Что внутри?

| Метод             | Путь                  | Описание                                    | Авторизация           |
|-------------------|-----------------------|---------------------------------------------|-----------------------|
| POST              | `/auth/token/{userId}`| Получить access и refresh токены по userId | Нет                   |
| GET               | `/auth/me`            | Информация о текущем пользователе           | AccessToken (Bearer)   |
| GET               | `/auth/logout`        | Черный список для access токена + выход     | AccessToken (Bearer)   |
| POST              | `/auth/refresh/{userId}`| Обновить access и refresh токены             | AccessToken (Bearer)   |

---

## Как запустить

Для быстрого запуска поднимаю все сервисы командой:

```bash
docker-compose up -d --build
````

Если нужно быстро запустить приложение с нуля — я использую:

```bash
./restart.sh
```

---

## Документация API

Вся документация доступна в Swagger UI:

👉 [http://localhost:8080/swagger](http://localhost:8080/swagger)

---

## Контакты

Если что, пишите в телегу: [@Romeoisfree9](https://t.me/Romeoisfree9)

---

Спасибо за внимание! Буду рад обратной связи! 💙
