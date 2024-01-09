<?php
// Подключаем файл с основными функциями
require_once('bootstrap.php');
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Авторизация/регистрация. PHP+MySQL+JavaScript,jQuery</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js" integrity="sha384-I7E8VVD/ismYTF4hNIPjVp/Zjvgyol6VFvRkX/vR+Vc4jQkC+hVqc2pM8ODewa9r" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js" integrity="sha384-BBtl+eGJRgqQAUMxJ7pMwbEyER4l1g+O15P+16Ep7Q9Q+zqX6gSbd85u4mG4QzX+" crossorigin="anonymous"></script>
</head>
<body>
    <div class="container-md container-fluid">
        <h1 class="my-3">Добро пожаловать на сайт</h1>
        <p class="h6">
            Вы зашли на сайт примера авторизации и регистрации пользователя. 
        </p>
        <p>
            Сейчас вы <?php echo (checkAuth()) ? "авторизованы" : "не авторизованы";?> на сайте. <br />
            <?php
            if (checkAuth())
            {
                echo "<p>Ваш логин: <strong>" . userData()['login'] . "</strong>.</p>";
                echo "<p>Вы можете <a href='/users.php?action=exit'>выйти</a> из системы.</p>";
            }
            else
            {
                ?>
                <p>На этом сайте вам доступно:</p>
                <ul class="list-unstyled">
                    <li>
                        <a href="/users.php">Авторизация и регистрация</a>
                    </li>
                </ul>
                <?php
            }
            ?>
        </p> 
    </div>
</body>
</html>