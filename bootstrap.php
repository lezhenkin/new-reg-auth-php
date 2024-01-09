<?php
/**
 * Проверяет статус авторизации пользователя
 * @param string $value может принимать для проверки конкретное значение логина или email
 * @return TRUE | FALSE
 */
function checkAuth(string $value = "") : bool
{
    // Статус авторизации пользователя
    $bIsAuth = FALSE;
    
    // Если сессия не запущена, запускаем её
    if (session_status() !== PHP_SESSION_ACTIVE)
    {
        session_start();
    }

    // Если не нужно проверить конкретные данные, и данные о пользователе записаны в сессию
    if (!empty($_SESSION['login']) && $value === "")
    {
        // Пользователь авторизован
        $bIsAuth = TRUE;
    }
    // Если нужно проверить конкретные данные
    elseif ($value !== "")
    {
        // Если в сессии сохранены логин или электропочта, а функции переданы значения для проверки, и они совпадают с теми, что хранятся в сессии
        if ((!empty($_SESSION['login']) || !empty($_SESSION['email'])) && ($_SESSION['login'] === $value || $_SESSION['email'] === $value))
        {
            // Пользователь авторизован
            $bIsAuth = TRUE;
        }
        // Если есть попытка подмены данных в сессии
        elseif ((!empty($_SESSION['login']) || !empty($_SESSION['email'])) && $_SESSION['login'] !== $value && $_SESSION['email'] !== $value)
        {
            // Стираем данные из сессии
            unset($_SESSION['login']);
            unset($_SESSION['email']);
            unset($_SESSION['password']);

            // Останавливаем работу скрипта
            die("<p>Несоответствие данных авторизации сессии. Работа остановлена</p>");
        }
    }
    
    // Возвращаем результат проверки
    return $bIsAuth;
}

/**
 * Подключается к СУБД
 */
function dbConnect()
{
    // Подключаем файл с конфигурацией для подключения к СУБД
    $aDbConfig = include('config/database.php');
    
    // Если настройки получены
    if (!empty($aDbConfig))
    {
        // Подключаемся к СУБД
        try {
            $dbh = new PDO("mysql:host={$aDbConfig['host']};dbname={$aDbConfig['dbname']}", 
                            $aDbConfig['user'], 
                            $aDbConfig['password'],
                        $aDbConfig['options']);
            
            // Результаты выборки из БД хотим видеть в виде объекта
            $dbh->setAttribute(PDO::FETCH_OBJ, TRUE);
        }
        // Если подключиться не удалось, останавливаем выполнение скрипта
        catch (PDOException $e)
        {
            // Показываем сообщение об ошибке
            die("<p><strong>При подключении к СУБД произошла ошибка:</strong> " . $e->getMessage() . "</p>");
        }

        return $dbh;
    }
}

/**
 * Авторизует пользователя с указанными данными
 * @param array $data
 * @return array
 */
function userAuthentication(array $data) : array
{
    // Данные, которые вернёт функция
    $aReturn = [
        'success' => FALSE,
        'message' => "При авторизации пользователя произошла ошибка",
        'data' => [],
        'type' => 'auth'
    ];

    // Проверяем, не был ли пользователь ранее авторизован
    if (checkAuth(strval(htmlspecialchars(trim($_POST['login'])))))
    {
        $aReturn = [
            'success' => TRUE,
            'message' => "Вы ранее уже авторизовались на сайте",
            'data' => [],
            'type' => 'auth'
        ];
    }
    // Если авторизации не было
    else 
    {
        try {
            // Если данные не были переданы
            if (empty($data))
            {
                throw new Exception("Не переданы параметры для авторизации пользователя");
            }
            // Если передаются данные для регистрации или какого-то иного действия
            elseif (empty($data['sign-in']))
            {
                throw new Exception("Необходимо передать данные для процедуры авторизации пользователя");
            }
        }
        catch (Exception $e)
        {
            die("<p><strong>При вызове функции авторизации пользователя произошла ошибка:</strong> {$e->getMessage()}</p>");
        }

        // Обрабатываем данные формы
        $sLogin = strval(htmlspecialchars(trim($_POST['login'])));
        $sPassword = strval(htmlspecialchars(trim($_POST['password'])));

        // Определяем тип авторизации: по логину или адресу электропочты
        $sType = NULL;
        $sType = match(validateEmail($sLogin)) {
                    TRUE => 'email',
                    FALSE => 'login'
        };

        // Если не передан пароль
        if (empty($sPassword))
        {
            $aReturn['message'] = "Поле пароля не было заполнено";
            $aReturn['data'] = $data;
        }
        else 
        {
            // Ищем соответствие переданной информации в БД
            $dbh = dbConnect();

            $stmt = $dbh->prepare("SELECT * FROM `users` WHERE `{$sType}` = :{$sType} AND `deleted` = 0");

            // Подготавливаем запрос
            $stmt->bindParam(":{$sType}", $sLogin);

            // Выполняем запрос
            $stmt->execute();

            // Если были найдены записи
            if ($stmt->rowCount())
            {
                $oUser = $stmt->fetch(PDO::FETCH_OBJ);
                
                /**
                 * Согласно документации к PHP, мы для подготовки пароля пользователя к сохранению в БД
                 * мы использовали функцию password_hash() https://www.php.net/manual/ru/function.password-hash
                 * Теперь для проверки пароля для авторизации нам нужно использовать функцию password_verify()
                 * https://www.php.net/manual/ru/function.password-verify.php
                 */

                // Проверяем пароль пользователя
                // Если хэш пароля совпадает
                if (password_verify($sPassword, $oUser->password))
                {
                    // Авторизуем пользователя
                    if (session_status() !== PHP_SESSION_ACTIVE)
                    {
                        session_start();
                    }
                    
                    $aReturn['success'] = TRUE;
                    $aReturn['message'] = "Вы успешно авторизовались на сайте";
                    $aReturn['data'] = $data;
                    $aReturn['data']['user_id'] = $oUser->id;

                    $_SESSION['login'] = $oUser->login;
                    $_SESSION['email'] = $oUser->email;
                    $_SESSION['password'] = $oUser->password;
                }
                else
                {
                    $aReturn['message'] = "Для учетной записи <strong>{$sLogin}</strong> указан неверный пароль";
                    $aReturn['data'] = $data;
                }
            }
        }
    }

    // Возвращаем результат авторизации вызову
    return $aReturn;
}

/**
 * Регистрирует пользователя с указанными параметрами
 * @param array $data
 * @return array
 */
function userRegistration(array $data) : array
{
    // Результат регистрации пользователя
    $bRegistration = FALSE;

    // Данные, которые вернёт функция
    $aReturn = [
        'success' => FALSE,
        'message' => "При регистрации пользователя произошла ошибка",
        'data' => [],
        'type' => 'reg'
    ];

    try {
        // Если данные не были переданы
        if (empty($data))
        {
            throw new Exception("Не переданы параметры для регистрации пользователя");
        }
        // Если передаются данные для авторизации или какого-то иного действия
        elseif (empty($data['sign-up']))
        {
            throw new Exception("Необходимо передать данные для процедуры регистрации пользователя");
        }
    }
    catch (Exception $e)
    {
        die("<p><strong>При вызове функции регистрации пользователя произошла ошибка:</strong> {$e->getMessage()}</p>");
    }

    // Обрабатываем данные формы
    $sLogin = strval(htmlspecialchars(trim($_POST['login'])));
    $sEmail = strval(htmlspecialchars(trim($_POST['email'])));
    $sPassword = strval(htmlspecialchars(trim($_POST['password'])));
    $sPassword2 = strval(htmlspecialchars(trim($_POST['password2'])));

    // Проверяем указанный email
    // Если указанные данные не являются корректным email, ничего не делаем дальше
    if (validateEmail($sEmail))
    {
        // Логин и пароли не могут быть пустыми
        if (empty($sLogin))
        {
            $aReturn['message'] = "Поле логина не было заполнено";
            $aReturn['data'] = $data;
        }
        elseif (empty($sPassword))
        {
            $aReturn['message'] = "Поле пароля не было заполнено";
            $aReturn['data'] = $data;
        }
        // Пароли должны быть идентичны
        elseif ($sPassword !== $sPassword2)
        {
            $aReturn['message'] = "Введенные пароли не совпадают";
            $aReturn['data'] = $data;
        }
        // Если логин не уникален
        elseif (isLoginExist($sLogin))
        {
            $aReturn['message'] = "Указанный вами логин ранее уже был зарегистрирован";
            $aReturn['data'] = $data;
        }
        // Если email не уникален
        elseif (isEmailExist($sEmail))
        {
            $aReturn['message'] = "Указанный вами email ранее уже был зарегистрирован";
            $aReturn['data'] = $data;
        }
        // Если все проверки прошли успешно, можно регистрировать пользователя
        else
        {
            $bRegistration = TRUE;
        }
    }
    else
    {
        $aReturn['message'] = "Указанное значение адреса электропочты не соответствует формату";
        $aReturn['data'] = $data;
    }

    // Регистрируем нового пользователя
    if ($bRegistration)
    {
        // Подключаемся к СУБД
        $dbh = dbConnect();

        // Создаем тело SQL-запроса
        $stmt = $dbh->prepare("INSERT INTO `users` (`login`, `email`, `password`) VALUES (:login, :email, :password)");

        /**
         * Согласно документации к PHP, мы для подготовки пароля пользователя к сохранению в БД
         * будем использовать функцию password_hash() https://www.php.net/manual/ru/function.password-hash
         * Причем, согласно рекомендации, начиная с версии PHP 8.0.0 не нужно указывать соль для пароля. Значит, и не будем
         */
        // Хэшируем пароль
        $sPassword = password_hash($sPassword, PASSWORD_BCRYPT);

        // Подготавливаем запрос
        $stmt->bindParam(':login', $sLogin);
        $stmt->bindParam(':email', $sEmail);
        $stmt->bindParam(':password', $sPassword);

        // Выполняем запрос
        $stmt->execute();

        // Если пользователь был успешно сохранен в БД
        if ($dbh->lastInsertId())
        {
            $aReturn['success'] = TRUE;
            $aReturn['message'] = "Пользователь с логином <strong>{$sLogin}</strong> и email <strong>{$sEmail}</strong> успешно зарегистрирован.";
            $aReturn['data']['user_id'] = $dbh->lastInsertId();

            // Уничтожаем данные от пользователя
            unset($_POST);
        }
    }
   
    // Возвращаем результат регистрации вызову
    return $aReturn;
}

// Проверка правильности email
function validateEmail(string $email) : bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

/**
 * Проверяет уникальность логина в системе
 * @param string $login
 * @return TRUE | FALSE
 */
function isLoginExist(string $login) : bool
{
    // Подключаемся к СУБД
    $dbh = dbConnect();

    // Проверяем уникальность логина в БД
    $sQuery = "SELECT * FROM `users` WHERE `login` = '{$login}' AND `deleted` = '0'";

    // Выполняем запрос
    try {
        $sth = $dbh->query($sQuery);
    }
    catch (PDOException $e)
    {
        die("<p><strong>При выполнении запроса произошла ошибка:</strong> {$e->getMessage()}</p>");
    }
    
    // Если логин уникален, в результате запроса не должно быть строк
    return $sth->rowCount() !== 0;
}

/**
 * Проверяет уникальность email в системе
 * @param string $email
 * @return TRUE | FALSE
 */
function isEmailExist(string $email) : bool
{
    // Подключаемся к СУБД
    $dbh = dbConnect();

    // Проверяем уникальность логина в БД
    $sQuery = "SELECT * FROM `users` WHERE `email` = '{$email}' AND `deleted` = '0'";

    // Выполняем запрос
    try {
        $sth = $dbh->query($sQuery);
    }
    catch (PDOException $e)
    {
        die("<p><strong>При выполнении запроса произошла ошибка:</strong> {$e->getMessage()}</p>");
    }

    // Если логин уникален, в результате запроса не должно быть строк
    return $sth->rowCount() !== 0;
}

// Возвращает данные об авторизованном пользователе
function userData() : array | NULL
{
    $return = NULL;

    if (checkAuth())
    {
        $return['login'] = $_SESSION['login'];
        $return['email'] = $_SESSION['email'];
    }

    return $return;
}

// Осуществляет выход пользователя из системы
function userLogout()
{
    // Запуск сессии, если она не активна
    if (session_status() !== PHP_SESSION_ACTIVE)
    {
        session_start();
    }

    // Уничтожение данных о пользователе в сессии
    unset($_SESSION['login']);
    unset($_SESSION['email']);
    unset($_SESSION['password']);
}
?>