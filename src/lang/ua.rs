lazy_static::lazy_static! {
pub static ref T: std::collections::HashMap<&'static str, &'static str> =
    [
        ("Status", "Статус"),
        ("Your Desktop", "Ваша стільниця"),
        ("desk_tip", "Ваша стільниця доступна з цим ідентифікатором і паролем"),
        ("Password", "Пароль"),
        ("Ready", "Готово"),
        ("Established", "Встановлено"),
        ("connecting_status", "Підключення до мережі RustDesk..."),
        ("Enable Service", "Включити службу"),
        ("Start Service", "Запустити службу"),
        ("Service is running", "Служба працює"),
        ("Service is not running", "Служба не запущена"),
        ("not_ready_status", "Не готово. Будь ласка, перевірте ваше підключення"),
        ("Control Remote Desktop", "Керування віддаленою стільницею"),
        ("Transfer File", "Надіслати файл"),
        ("Connect", "Підключитися"),
        ("Recent Sessions", "Нещодавні сеанси"),
        ("Address Book", "Адресна книга"),
        ("Confirmation", "Підтвердження"),
        ("TCP Tunneling", "TCP-тунелювання"),
        ("Remove", "Видалити"),
        ("Refresh random password", "Оновити випадковий пароль"),
        ("Set your own password", "Встановити свій пароль"),
        ("Enable Keyboard/Mouse", "Увімкнути клавіатуру/мишу"),
        ("Enable Clipboard", "Увімкнути буфер обміну"),
        ("Enable File Transfer", "Увімкнути передачу файлів"),
        ("Enable TCP Tunneling", "Увімкнути тунелювання TCP"),
        ("IP Whitelisting", "Список дозволених IP-адрес"),
        ("ID/Relay Server", "ID/Сервер ретрансляції"),
        ("Import Server Config", "Імпортувати конфігурацію сервера"),
        ("Export Server Config", "Експортувати конфігурацію сервера"),
        ("Import server configuration successfully", "Конфігурацію сервера успішно імпортовано"),
        ("Export server configuration successfully", "Конфігурацію сервера успішно експортовано"),
        ("Invalid server configuration", "Неправильна конфігурація сервера"),
        ("Clipboard is empty", "Буфер обміну порожній"),
        ("Stop service", "Зупинити службу"),
        ("Change ID", "Змінити ID"),
        ("Your new ID", "Ваш новий ID"),
        ("length %min% to %max%", "від %min% до %max% символів"),
        ("starts with a letter", "починається з літери"),
        ("allowed characters", "дозволені символи"),
        ("id_change_tip", "Допускаються лише символи a-z, A-Z, 0-9 і _ (підкреслення). Першою повинна бути літера a-z, A-Z. В межах від 6 до 16 символів"),
        ("Website", "Веб-сайт"),
        ("About", "Про RustDesk"),
        ("Slogan_tip", "Створено з душею в цьому хаотичному світі!"),
        ("Privacy Statement", "Декларація про конфіденційність"),
        ("Mute", "Вимкнути звук"),
        ("Build Date", "Дата збірки"),
        ("Version", "Версія"),
        ("Home", "Домівка"),
        ("Audio Input", "Аудіовхід"),
        ("Enhancements", "Покращення"),
        ("Hardware Codec", "Апаратний кодек"),
        ("Adaptive Bitrate", "Адаптивна швидкість потоку"),
        ("ID Server", "ID-сервер"),
        ("Relay Server", "Сервер ретрансляції"),
        ("API Server", "API-сервер"),
        ("invalid_http", "Повинна починатися з http:// або https://"),
        ("Invalid IP", "Неправильна IP-адреса"),
        ("Invalid format", "Неправильний формат"),
        ("server_not_support", "Наразі не підтримується сервером"),
        ("Not available", "Недоступно"),
        ("Too frequent", "Занадто часто"),
        ("Cancel", "Скасувати"),
        ("Skip", "Пропустити"),
        ("Close", "Закрити"),
        ("Retry", "Спробувати знову"),
        ("OK", "OK"),
        ("Password Required", "Потрібен пароль"),
        ("Please enter your password", "Будь ласка, введіть ваш пароль"),
        ("Remember password", "Запамʼятати пароль"),
        ("Wrong Password", "Неправильний пароль"),
        ("Do you want to enter again?", "Ви хочете знову увійти?"),
        ("Connection Error", "Помилка підключення"),
        ("Error", "Помилка"),
        ("Reset by the peer", "Віддалений пристрій скинув підключення"),
        ("Connecting...", "Підключення..."),
        ("Connection in progress. Please wait.", "Виконується підключення. Будь ласка, зачекайте."),
        ("Please try 1 minute later", "Спробуйте через 1 хвилину"),
        ("Login Error", "Помилка входу"),
        ("Successful", "Операція успішна"),
        ("Connected, waiting for image...", "Підключено, очікування зображення..."),
        ("Name", "Імʼя"),
        ("Type", "Тип"),
        ("Modified", "Змінено"),
        ("Size", "Розмір"),
        ("Show Hidden Files", "Показати приховані файли"),
        ("Receive", "Отримати"),
        ("Send", "Надіслати"),
        ("Refresh File", "Оновити файл"),
        ("Local", "Локальний"),
        ("Remote", "Віддалений"),
        ("Remote Computer", "Віддалений компʼютер"),
        ("Local Computer", "Локальний компʼютер"),
        ("Confirm Delete", "Підтвердити видалення"),
        ("Delete", "Видалити"),
        ("Properties", "Властивості"),
        ("Multi Select", "Багатоелементний вибір"),
        ("Select All", "Вибрати все"),
        ("Unselect All", "Скасувати вибір"),
        ("Empty Directory", "Порожня тека"),
        ("Not an empty directory", "Тека не порожня"),
        ("Are you sure you want to delete this file?", "Ви впевнені, що хочете видалити цей файл?"),
        ("Are you sure you want to delete this empty directory?", "Ви впевнені, що хочете видалити порожню теку?"),
        ("Are you sure you want to delete the file of this directory?", "Ви впевнені, що хочете видалити файл із цієї теки?"),
        ("Do this for all conflicts", "Це стосується всіх конфліктів"),
        ("This is irreversible!", "Це незворотна дія!"),
        ("Deleting", "Видалення"),
        ("files", "файли"),
        ("Waiting", "Очікування"),
        ("Finished", "Завершено"),
        ("Speed", "Швидкість"),
        ("Custom Image Quality", "Користувацька якість зображення"),
        ("Privacy mode", "Режим конфіденційності"),
        ("Block user input", "Блокувати користувацьке введення"),
        ("Unblock user input", "Розблокувати користувацьке введення"),
        ("Adjust Window", "Налаштувати вікно"),
        ("Original", "Оригінал"),
        ("Shrink", "Зменшити"),
        ("Stretch", "Розтягнути"),
        ("Scrollbar", "Смуга прокрутки"),
        ("ScrollAuto", "Автоматична прокрутка"),
        ("Good image quality", "Хороша якість зображення"),
        ("Balanced", "Збалансована"),
        ("Optimize reaction time", "Оптимізувати час реакції"),
        ("Custom", "Користувацька"),
        ("Show remote cursor", "Показати віддалений вказівник"),
        ("Show quality monitor", "Показати якість"),
        ("Disable clipboard", "Вимкнути буфер обміну"),
        ("Lock after session end", "Блокування після завершення сеансу"),
        ("Insert", "Вставити"),
        ("Insert Lock", "Встановити замок"),
        ("Refresh", "Оновити"),
        ("ID does not exist", "ID не існує"),
        ("Failed to connect to rendezvous server", "Не вдалося підключитися до проміжного сервера"),
        ("Please try later", "Будь ласка, спробуйте пізніше"),
        ("Remote desktop is offline", "Віддалена стільниця не в мережі"),
        ("Key mismatch", "Невідповідність ключів"),
        ("Timeout", "Тайм-аут"),
        ("Failed to connect to relay server", "Не вдалося підключитися до сервера реле"),
        ("Failed to connect via rendezvous server", "Не вдалося підключитися через проміжний сервер"),
        ("Failed to connect via relay server", "Не вдалося підключитися через сервер реле"),
        ("Failed to make direct connection to remote desktop", "Не вдалося встановити пряме підключення до віддаленої стільниці"),
        ("Set Password", "Встановити пароль"),
        ("OS Password", "Пароль ОС"),
        ("install_tip", "Через UAC в деяких випадках RustDesk може працювати некоректно на віддаленому вузлі. Щоб уникнути UAC, натисніть кнопку нижче для встановлення RustDesk в системі"),
        ("Click to upgrade", "Натисніть, щоб перевірити наявність оновлень"),
        ("Click to download", "Натисніть, щоб завантажити"),
        ("Click to update", "Натисніть, щоб оновити"),
        ("Configure", "Налаштувати"),
        ("config_acc", "Для віддаленого керування вашою стільницею, вам необхідно надати RustDesk дозволи \"Доступності\""),
        ("config_screen", "Для віддаленого доступу до вашої стільниці,вам необхідно надати RustDesk дозволи на \"Запис екрану\""),
        ("Installing ...", "Встановлюється..."),
        ("Install", "Встановити"),
        ("Installation", "Встановлення"),
        ("Installation Path", "Шлях встановлення"),
        ("Create start menu shortcuts", "Створити ярлики меню \"Пуск\""),
        ("Create desktop icon", "Створити значок на стільниці"),
        ("agreement_tip", "Починаючи встановлення, ви приймаєте умови ліцензійної угоди"),
        ("Accept and Install", "Прийняти та встановити"),
        ("End-user license agreement", "Ліцензійна угода з кінцевим користувачем"),
        ("Generating ...", "Генерація..."),
        ("Your installation is lower version.", "У вас встановлена більш рання версія"),
        ("not_close_tcp_tip", "Не закривайте це вікно під час використання тунелю"),
        ("Listening ...", "Очікуємо ..."),
        ("Remote Host", "Віддалена машина"),
        ("Remote Port", "Віддалений порт"),
        ("Action", "Дія"),
        ("Add", "Додати"),
        ("Local Port", "Локальний порт"),
        ("Local Address", "Локальна адреса"),
        ("Change Local Port", "Змінити локальний порт"),
        ("setup_server_tip", "Для пришвидшення зʼєднання, будь ласка, налаштуйте власний сервер"),
        ("Too short, at least 6 characters.", "Занадто коротко, мінімум 6 символів"),
        ("The confirmation is not identical.", "Підтвердження не збігається"),
        ("Permissions", "Дозволи"),
        ("Accept", "Прийняти"),
        ("Dismiss", "Відхилити"),
        ("Disconnect", "Відʼєднати"),
        ("Allow using keyboard and mouse", "Дозволити використання клавіатури та миші"),
        ("Allow using clipboard", "Дозволити використання буфера обміну"),
        ("Allow hearing sound", "Дозволити передачу звуку"),
        ("Allow file copy and paste", "Дозволити копіювання та вставку файлів"),
        ("Connected", "Підключено"),
        ("Direct and encrypted connection", "Пряме та зашифроване підключення"),
        ("Relayed and encrypted connection", "Релейне та зашифроване підключення"),
        ("Direct and unencrypted connection", "Пряме та незашифроване підключення"),
        ("Relayed and unencrypted connection", "Релейне та незашифроване підключення"),
        ("Enter Remote ID", "Введіть віддалений ID"),
        ("Enter your password", "Введіть пароль"),
        ("Logging in...", "Вхід..."),
        ("Enable RDP session sharing", "Включити загальний доступ до сеансу RDP"),
        ("Auto Login", "Автоматичний вхід (дійсний, тільки якщо ви встановили \"Завершення користувацького сеансу після завершення віддаленого підключення\")"),
        ("Enable Direct IP Access", "Увімкнути прямий IP-доступ"),
        ("Rename", "Перейменувати"),
        ("Space", "Місце"),
        ("Create Desktop Shortcut", "Створити ярлик на стільниці"),
        ("Change Path", "Змінити шлях"),
        ("Create Folder", "Створити теку"),
        ("Please enter the folder name", "Будь ласка, введіть назву для теки"),
        ("Fix it", "Виправити"),
        ("Warning", "Попередження"),
        ("Login screen using Wayland is not supported", "Вхід в систему з використанням Wayland не підтримується"),
        ("Reboot required", "Потрібне перезавантаження"),
        ("Unsupported display server", "Графічний сервер не підтримується"),
        ("x11 expected", "Очікується X11"),
        ("Port", "Порт"),
        ("Settings", "Налаштування"),
        ("Username", "Імʼя користувача"),
        ("Invalid port", "Неправильний порт"),
        ("Closed manually by the peer", "Завершено вручну з боку віддаленого пристрою"),
        ("Enable remote configuration modification", "Дозволити віддалену зміну конфігурації"),
        ("Run without install", "Запустити без встановлення"),
        ("Connect via relay", "Підключитися через реле"),
        ("Always connect via relay", "Завжди підключатися через реле"),
        ("whitelist_tip", "Тільки IP-адреси з білого списку можуть отримати доступ до мене"),
        ("Login", "Увійти"),
        ("Verify", "Підтвердити"),
        ("Remember me", "Запамʼятати мене"),
        ("Trust this device", "Довірений пристрій"),
        ("Verification code", "Код підтвердження"),
        ("verification_tip", "Виявлено новий пристрій, код підтвердження надіслано на зареєстровану email-адресу, введіть код підтвердження для продовження авторизації."),
        ("Logout", "Вийти"),
        ("Tags", "Ключові слова"),
        ("Search ID", "Пошук за ID"),
        ("whitelist_sep", "Розділені комою, крапкою з комою, пробілом або новим рядком"),
        ("Add ID", "Додати ID"),
        ("Add Tag", "Додати ключове слово"),
        ("Unselect all tags", "Скасувати вибір усіх тегів"),
        ("Network error", "Помилка мережі"),
        ("Username missed", "Імʼя користувача відсутнє"),
        ("Password missed", "Забули пароль"),
        ("Wrong credentials", "Неправильні дані"),
        ("The verification code is incorrect or has expired", "Код підтвердження некоректний або протермінований"),
        ("Edit Tag", "Редагувати тег"),
        ("Unremember Password", "Не зберігати пароль"),
        ("Favorites", "Вибране"),
        ("Add to Favorites", "Додати в обране"),
        ("Remove from Favorites", "Видалити з обраного"),
        ("Empty", "Пусто"),
        ("Invalid folder name", "Неприпустима назва теки"),
        ("Socks5 Proxy", "Проксі-сервер Socks5"),
        ("Hostname", "Назва пристрою"),
        ("Discovered", "Знайдено"),
        ("install_daemon_tip", "Для запуску під час завантаження, вам необхідно встановити системну службу"),
        ("Remote ID", "Віддалений ідентифікатор"),
        ("Paste", "Вставити"),
        ("Paste here?", "Вставити сюди?"),
        ("Are you sure to close the connection?", "Ви впевнені, що хочете завершити підключення?"),
        ("Download new version", "Завантажити нову версію"),
        ("Touch mode", "Сенсорний режим"),
        ("Mouse mode", "Режим миші"),
        ("One-Finger Tap", "Дотик одним пальцем"),
        ("Left Mouse", "Ліва кнопка миші"),
        ("One-Long Tap", "Одне довге натискання пальцем"),
        ("Two-Finger Tap", "Дотик двома пальцями"),
        ("Right Mouse", "Права миша"),
        ("One-Finger Move", "Рух одним пальцем"),
        ("Double Tap & Move", "Подвійне натискання та переміщення"),
        ("Mouse Drag", "Перетягування мишею"),
        ("Three-Finger vertically", "Трьома пальцями по вертикалі"),
        ("Mouse Wheel", "Коліщатко миші"),
        ("Two-Finger Move", "Рух двома пальцями"),
        ("Canvas Move", "Переміщення полотна"),
        ("Pinch to Zoom", "Стисніть, щоб збільшити"),
        ("Canvas Zoom", "Масштаб полотна"),
        ("Reset canvas", "Відновлення полотна"),
        ("No permission of file transfer", "Немає дозволу на передачу файлів"),
        ("Note", "Примітка"),
        ("Connection", "Зʼєднання"),
        ("Share Screen", "Поділитися екраном"),
        ("Chat", "Чат"),
        ("Total", "Всього"),
        ("items", "елементи"),
        ("Selected", "Обрано"),
        ("Screen Capture", "Захоплення екрана"),
        ("Input Control", "Вхідний контроль"),
        ("Audio Capture", "Захоплення аудіо"),
        ("File Connection", "Файлове підключення"),
        ("Screen Connection", "Підключення екрана"),
        ("Do you accept?", "Ви згодні?"),
        ("Open System Setting", "Відкрити налаштування системи"),
        ("How to get Android input permission?", "Як отримати дозвіл на введення Android?"),
        ("android_input_permission_tip1", "Для того, щоб віддалений пристрій міг керувати вашим Android-пристроєм за допомогою миші або торкання, вам необхідно дозволити RustDesk використовувати службу \"Спеціальні можливості\"."),
        ("android_input_permission_tip2", "Перейдіть на наступну сторінку системних налаштувань, знайдіть та увійдіть у [Встановлені служби], увімкніть службу [RustDesk Input]."),
        ("android_new_connection_tip", "Отримано новий запит на керування вашим поточним пристроєм."),
        ("android_service_will_start_tip", "Увімкнення захоплення екрана автоматично запускає службу, дозволяючи іншим пристроям запитувати підключення до вашого пристрою."),
        ("android_stop_service_tip", "Зупинка служби автоматично завершить всі встановлені зʼєднання."),
        ("android_version_audio_tip", "Поточна версія Android не підтримує захоплення звуку, оновіть її до Android 10 або вище."),
        ("android_start_service_tip", "Натисніть [Запустити службу] або увімкніть дозвіл на [Захоплення екрана], щоб запустити службу спільного доступу до екрана."),
        ("android_permission_may_not_change_tip", "Дозволи для встановлених зʼєднань можуть не змінитися миттєво аж до перепідключення."),
        ("Account", "Акаунт"),
        ("Overwrite", "Перезаписати"),
        ("This file exists, skip or overwrite this file?", "Цей файл існує, пропустити чи перезаписати файл?"),
        ("Quit", "Вийти"),
        ("doc_mac_permission", "https://rustdesk.com/docs/en/manual/mac/#enable-permissions"),
        ("Help", "Допомога"),
        ("Failed", "Не вдалося"),
        ("Succeeded", "Успішно"),
        ("Someone turns on privacy mode, exit", "Хтось вмикає режим конфіденційності, вихід"),
        ("Unsupported", "Не підтримується"),
        ("Peer denied", "Відхилено віддаленим пристроєм"),
        ("Please install plugins", "Будь ласка, встановіть плагіни"),
        ("Peer exit", "Вийти з віддаленого пристрою"),
        ("Failed to turn off", "Не вдалося вимкнути"),
        ("Turned off", "Вимкнений"),
        ("In privacy mode", "У режимі конфіденційності"),
        ("Out privacy mode", "Вихід із режиму конфіденційності"),
        ("Language", "Мова"),
        ("Keep RustDesk background service", "Зберегти фонову службу RustDesk"),
        ("Ignore Battery Optimizations", "Ігнорувати оптимізації батареї"),
        ("android_open_battery_optimizations_tip", "Перейдіть на наступну сторінку налаштувань"),
        ("Start on Boot", "Автозапуск"),
        ("Start the screen sharing service on boot, requires special permissions", "Запустити службу службу спільного доступу до екрана під час завантаження, потребує спеціальних дозволів"),
        ("Connection not allowed", "Підключення не дозволено"),
        ("Legacy mode", "Застарілий режим"),
        ("Map mode", "Режим карти"),
        ("Translate mode", "Режим перекладу"),
        ("Use permanent password", "Використовувати постійний пароль"),
        ("Use both passwords", "Використовувати обидва паролі"),
        ("Set permanent password", "Встановити постійний пароль"),
        ("Enable Remote Restart", "Увімкнути віддалений перезапуск"),
        ("Allow remote restart", "Дозволити віддалений перезапуск"),
        ("Restart Remote Device", "Перезапустити віддалений пристрій"),
        ("Are you sure you want to restart", "Ви впевнені, що хочете виконати перезапуск?"),
        ("Restarting Remote Device", "Перезавантаження віддаленого пристрою"),
        ("remote_restarting_tip", "Віддалений пристрій перезапускається. Будь ласка, закрийте це повідомлення та через деякий час перепідʼєднайтесь, використовуючи постійний пароль."),
        ("Copied", "Скопійовано"),
        ("Exit Fullscreen", "Вийти з повноекранного режиму"),
        ("Fullscreen", "Повноекранний"),
        ("Mobile Actions", "Мобільні дії"),
        ("Select Monitor", "Виберіть монітор"),
        ("Control Actions", "Дії для керування"),
        ("Display Settings", "Налаштування дисплею"),
        ("Ratio", "Співвідношення"),
        ("Image Quality", "Якість зображення"),
        ("Scroll Style", "Стиль прокрутки"),
        ("Show Toolbar", "Показати панель інструментів"),
        ("Hide Toolbar", "Приховати панель інструментів"),
        ("Direct Connection", "Пряме підключення"),
        ("Relay Connection", "Релейне підключення"),
        ("Secure Connection", "Безпечне підключення"),
        ("Insecure Connection", "Небезпечне підключення"),
        ("Scale original", "Оригінал масштабу"),
        ("Scale adaptive", "Масштаб адаптивний"),
        ("General", "Загальні"),
        ("Security", "Безпека"),
        ("Theme", "Тема"),
        ("Dark Theme", "Темна тема"),
        ("Light Theme", "Світла тема"),
        ("Dark", "Темна"),
        ("Light", "Світла"),
        ("Follow System", "Як в системі"),
        ("Enable hardware codec", "Увімкнути апаратний кодек"),
        ("Unlock Security Settings", "Розблокувати налаштування безпеки"),
        ("Enable Audio", "Увімкнути аудіо"),
        ("Unlock Network Settings", "Розблокувати мережеві налаштування"),
        ("Server", "Сервер"),
        ("Direct IP Access", "Прямий IP доступ"),
        ("Proxy", "Проксі"),
        ("Apply", "Застосувати"),
        ("Disconnect all devices?", "Відʼєднати всі прилади?"),
        ("Clear", "Очистити"),
        ("Audio Input Device", "Пристрій введення звуку"),
        ("Use IP Whitelisting", "Використовувати білий список IP"),
        ("Network", "Мережа"),
        ("Enable RDP", "Увімкнути RDP"),
        ("Pin Toolbar", "Закріпити панель інструментів"),
        ("Unpin Toolbar", "Відкріпити панель інструментів"),
        ("Recording", "Запис"),
        ("Directory", "Директорія"),
        ("Automatically record incoming sessions", "Автоматично записувати вхідні сеанси"),
        ("Change", "Змінити"),
        ("Start session recording", "Розпочати запис сесії"),
        ("Stop session recording", "Закінчити запис сесії"),
        ("Enable Recording Session", "Увімкнути запис сесії"),
        ("Allow recording session", "Дозволити запис сеансу"),
        ("Enable LAN Discovery", "Увімкнути пошук локальної мережі"),
        ("Deny LAN Discovery", "Заборонити виявлення локальної мережі"),
        ("Write a message", "Написати повідомлення"),
        ("Prompt", "Підказка"),
        ("Please wait for confirmation of UAC...", "Будь ласка, зачекайте підтвердження UAC..."),
        ("elevated_foreground_window_tip", "Поточне вікно віддаленої стільниці потребує розширених прав для роботи, тому наразі неможливо використати мишу та клавіатуру. Ви можете запропонувати віддаленому користувачу згорнути поточне вікно чи натиснути кнопку розширення прав у вікні керування підключеннями. Для уникнення цієї проблеми, рекомендується встановити програму на віддаленому пристрої"),
        ("Disconnected", "Відʼєднано"),
        ("Other", "Інше"),
        ("Confirm before closing multiple tabs", "Підтверджувати перед закриттям кількох вкладок"),
        ("Keyboard Settings", "Налаштування клавіатури"),
        ("Full Access", "Повний доступ"),
        ("Screen Share", "Демонстрація екрану"),
        ("Wayland requires Ubuntu 21.04 or higher version.", "Wayland потребує Ubuntu 21.04 або новішої версії."),
        ("Wayland requires higher version of linux distro. Please try X11 desktop or change your OS.", "Для Wayland потрібна новіша версія дистрибутива Linux. Будь ласка, спробуйте стільницю на X11 або змініть свою ОС."),
        ("JumpLink", "Перегляд"),
        ("Please Select the screen to be shared(Operate on the peer side).", "Будь ласка, виберіть екран, до якого потрібно надати доступ (на віддаленому пристрої)."),
        ("Show RustDesk", "Показати RustDesk"),
        ("This PC", "Цей ПК"),
        ("or", "чи"),
        ("Continue with", "Продовжити з"),
        ("Elevate", "Розширення прав"),
        ("Zoom cursor", "Збільшити вказівник"),
        ("Accept sessions via password", "Підтверджувати сеанси паролем"),
        ("Accept sessions via click", "Підтверджувати сеанси натисканням"),
        ("Accept sessions via both", "Підтверджувати сеанси обома способами"),
        ("Please wait for the remote side to accept your session request...", "Буль ласка, зачекайте, поки віддалена сторона підтвердить запит на сеанс..."),
        ("One-time Password", "Одноразовий пароль"),
        ("Use one-time password", "Використати одноразовий пароль"),
        ("One-time password length", "Довжина одноразового пароля"),
        ("Request access to your device", "Дати запит щодо доступ до свого пристрою"),
        ("Hide connection management window", "Приховати вікно керування підключеннями"),
        ("hide_cm_tip", "Дозволено приховати лише якщо сеанс підтверджується постійним паролем"),
        ("wayland_experiment_tip", "Підтримка Wayland на експериментальній стадії, будь ласка, використовуйте X11, якщо необхідний автоматичний доступ."),
        ("Right click to select tabs", "Правий клік для вибору вкладки"),
        ("Skipped", "Пропущено"),
        ("Add to Address Book", "Додати IP до Адресної книги"),
        ("Group", "Група"),
        ("Search", "Пошук"),
        ("Closed manually by web console", "Закрито вручну з веб-консолі"),
        ("Local keyboard type", "Тип локальної клавіатури"),
        ("Select local keyboard type", "Оберіть тип локальної клавіатури"),
        ("software_render_tip", "Якщо ви використовуєте відеокарту Nvidia на Linux, і віддалене вікно закривається відразу після підключення, то перехід на вільний драйвер Nouveau та увімкнення програмного рендерингу може допомогти. Для застосування змін необхідно перезапустити програму."),
        ("Always use software rendering", "Завжди використовувати програмний рендеринг"),
        ("config_input", "Для віддаленого керування віддаленою стільницею з клавіатури, вам необхідно надати Rustdesk дозволи на \"Відстеження введення\""),
        ("config_microphone", "Для можливості віддаленої розмови, вам необхідно надати RustDesk дозвіл на \"Запис аудіо\""),
        ("request_elevation_tip", "Ви також можете надіслати запит на розширення прав, в разі присутності особи з віддаленого боку."),
        ("Wait", "Зачекайте"),
        ("Elevation Error", "Невдала спроба розширення прав"),
        ("Ask the remote user for authentication", "Попросіть віддаленого користувача пройти автентифікацію"),
        ("Choose this if the remote account is administrator", "Виберіть це, якщо віддалений обліковий запис є адміністративним"),
        ("Transmit the username and password of administrator", "Передайте імʼя користувача та пароль адміністратора"),
        ("still_click_uac_tip", "Досі необхідне підтвердження UAC з боку віддаленого користувача"),
        ("Request Elevation", "Запит на розширення прав"),
        ("wait_accept_uac_tip", "Будь ласка, очікуйте підтвердження діалогу UAC з боку віддаленого користувача."),
        ("Elevate successfully", "Успішне розширення прав"),
        ("uppercase", "верхній регістр"),
        ("lowercase", "нижній регістр"),
        ("digit", "цифра"),
        ("special character", "спецсимвол"),
        ("length>=8", "довжина>=8"),
        ("Weak", "Слабкий"),
        ("Medium", "Середній"),
        ("Strong", "Сильний"),
        ("Switch Sides", "Поміняти місцями"),
        ("Please confirm if you want to share your desktop?", "Будь ласка, підтвердіть дозвіл на спільне використання стільниці"),
        ("Display", "Екран"),
        ("Default View Style", "Типовий стиль перегляду"),
        ("Default Scroll Style", "Типовий стиль гортання"),
        ("Default Image Quality", "Типова якість зображення"),
        ("Default Codec", "Типовий кодек"),
        ("Bitrate", "Бітрейт"),
        ("FPS", "FPS"),
        ("Auto", "Авто"),
        ("Other Default Options", "Інші типові параметри"),
        ("Voice call", "Голосовий виклик"),
        ("Text chat", "Текстовий чат"),
        ("Stop voice call", "Завершити голосовий виклик"),
        ("relay_hint_tip", "Якщо відсутня можливості підключитись напряму, ви можете спробувати підключення по реле. \nТакож, якщо ви хочете відразу використовувати реле, можна додати суфікс \"/r\" до ID, або ж вибрати опцію \"Завжди підключатися через реле\" в картці нещодавніх сеансів."),
        ("Reconnect", "Перепідключитися"),
        ("Codec", "Кодек"),
        ("Resolution", "Роздільна здатність"),
        ("No transfers in progress", "Наразі нічого не пересилається"),
        ("Set one-time password length", "Вказати довжину одноразового пароля"),
        ("install_cert_tip", "Додати сертифікат Rustdesk"),
        ("comfirm_install_cert_tip", "Це сертифікат тестування Rustdesk, якому можна довіряти. За потреби сертифікат буде використано для погодження та встановлення драйверів Rustdesk."),
        ("RDP Settings", "Налаштування RDP"),
        ("Sort by", "Сортувати за"),
        ("New Connection", "Нове підключення"),
        ("Restore", "Відновити"),
        ("Minimize", "Згорнути"),
        ("Maximize", "Розгорнути"),
        ("Your Device", "Вам пристрій"),
        ("empty_recent_tip", "Овва, відсутні нещодавні сеанси!\nСаме час запланувати нове підключення."),
        ("empty_favorite_tip", "Досі немає улюблених вузлів?\nДавайте організуємо нове підключення та додамо його до улюблених!"),
        ("empty_lan_tip", "О ні, схоже ми поки не виявили жодного віддаленого пристрою"),
        ("empty_address_book_tip", "Ой лишенько, схоже до вашої адресної книги немає жодного віддаленого пристрою"),
        ("eg: admin", "напр. admin"),
        ("Empty Username", "Незаповнене імʼя"),
        ("Empty Password", "Незаповнений пароль"),
        ("Me", "Я"),
        ("identical_file_tip", "Цей файл ідентичний з тим, що на вузлі"),
        ("show_monitors_tip", "Показувати монітори на панелі інструментів"),
        ("View Mode", "Режим перегляду"),
        ("login_linux_tip", "Вам необхідно залогуватися у віддалений акаунт Linux, щоб увімкнути стільничний сеанс X"),
        ("verify_rustdesk_password_tip", "Перевірте пароль Rustdesk"),
        ("remember_account_tip", "Запамʼятати цей акаунт"),
        ("os_account_desk_tip", "Цей акаунт використовується для входу до віддаленої ОС та вмикання сеансу стільниці в неграфічному режимі"),
        ("OS Account", "Користувач ОС"),
        ("another_user_login_title_tip", "Інший користувач вже залогований"),
        ("another_user_login_text_tip", "Відʼєднатися"),
        ("xorg_not_found_title_tip", "Xorg не знайдено"),
        ("xorg_not_found_text_tip", "Будь ласка, встановіть Xorg"),
        ("no_desktop_title_tip", "Жодне стільничне середовище не доступне"),
        ("no_desktop_text_tip", "Будь ласка, встановіть стільничне середовище GNOME"),
        ("No need to elevate", "Немає потреби в розширенні прав"),
        ("System Sound", "Системний звук"),
        ("Default", "Типово"),
        ("New RDP", "Нове RDP"),
        ("Fingerprint", "Відбитки пальців"),
        ("Copy Fingerprint", "Копіювати відбитки пальців"),
        ("no fingerprints", "немає відбитків пальців"),
        ("Select a peer", "Оберіть віддалений пристрій"),
        ("Select peers", "Оберіть віддалені пристрої"),
        ("Plugins", "Плагіни"),
        ("Uninstall", "Видалити"),
        ("Update", "Оновити"),
        ("Enable", "Увімкнути"),
        ("Disable", "Вимкнути"),
        ("Options", "Опції"),
        ("resolution_original_tip", "Початкова роздільна здатність"),
        ("resolution_fit_local_tip", "Припасувати поточну роздільну здатність"),
        ("resolution_custom_tip", "Користувацька роздільна здатність"),
        ("Collapse toolbar", "Згорнути панель інструментів"),
        ("Accept and Elevate", "Погодитись та розширити права"),
        ("accept_and_elevate_btn_tooltip", "Погодити підключення та розширити дозволи UAC."),
        ("clipboard_wait_response_timeout_tip", "Вийшов час очікування копіювання."),
        ("Incoming connection", "Вхідне підключення"),
        ("Outgoing connection", "Вихідне підключення"),
        ("Exit", "Вийти"),
        ("Open", "Відкрити"),
        ("logout_tip", "Ви впевнені, що хочете вилогуватися?"),
        ("Service", ""),
        ("Start", ""),
        ("Stop", ""),
    ].iter().cloned().collect();
}
