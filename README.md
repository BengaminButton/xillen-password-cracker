# XILLEN Password Cracker

## Описание
Мощный инструмент для взлома хешей паролей с поддержкой множества алгоритмов хеширования и многопоточности.

## Возможности
- Поддержка MD5, SHA1, SHA256, SHA512, NTLM хешей
- Автоматическое определение типа хеша
- Многопоточный взлом для максимальной производительности
- Работа с файлами хешей и одиночными хешами
- Сохранение результатов в CSV формате
- Статистика успешности взлома

## Установка
```bash
git clone https://github.com/BengaminButton/xillen-password-cracker
cd xillen-password-cracker
pip install -r requirements.txt
```

## Использование
```bash
# Взлом одиночного хеша
python password_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt

# Взлом файла хешей
python password_cracker.py hashes.txt -w wordlist.txt -t md5

# Многопоточный взлом
python password_cracker.py hashes.txt -w wordlist.txt -j 8

# Сохранение результатов
python password_cracker.py hashes.txt -w wordlist.txt -o results.csv
```

## Примеры
```bash
# Взлом MD5 хеша
python password_cracker.py 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt

# Взлом NTLM хешей
python password_cracker.py ntlm_hashes.txt -w wordlist.txt -t ntlm

# Автоопределение типа хеша
python password_cracker.py hashes.txt -w wordlist.txt
```

## Выходные данные
- Статистика по каждому хешу
- Время выполнения
- Процент успешности
- CSV файл с результатами

## Обнаруживаемые уязвимости
- Слабые пароли
- Хеши без соли
- Устаревшие алгоритмы хеширования
- Пароли из словарей

## Рекомендации по безопасности
- Используйте сложные пароли
- Добавляйте соль к хешам
- Используйте современные алгоритмы (bcrypt, Argon2)
- Регулярно обновляйте пароли
- Мониторьте попытки взлома

## Требования
- Python 3.7+
- Словарь паролей
- Достаточно оперативной памяти для загрузки словаря

## Производительность
- Скорость: до 1M хешей/сек (зависит от оборудования)
- Память: ~100MB на 1M слов в словаре
- Многопоточность: до 16 потоков

## Авторы
- **@Bengamin_Button** - Основной разработчик
- **@XillenAdapter** - Технический консультант

## Ссылки
- Веб-сайт: https://benjaminbutton.ru/
- XILLEN: https://xillenkillers.ru/
- Telegram: t.me/XillenAdapter
