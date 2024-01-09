<?php
// Подключаем файл с основными функциями
require_once('bootstrap.php');

// Здесь будет храниться результат обработки форм
$aFormHandlerResult = [];

// Если была заполнена форма
if (!empty($_POST['sign-in']) || !empty($_POST['sign-up']))
{
    // Если заполнена форма авторизации
    if (!empty($_POST['sign-in']))
    {
        $aFormHandlerResult = userAuthentication($_POST);
    }
    // Если заполнена форма регистрации
    elseif (!empty($_POST['sign-up']))
    {
        // Регистрируем пользователя
        $aFormHandlerResult = userRegistration($_POST);
    }
}

// Если пользователь желает разлогиниться
if (!empty($_GET['action']) && $_GET['action'] == "exit" && checkAuth())
{
    // Завершаем сеанс пользователя
    userLogout();
}

// Если пользователь вводил данные, покажем их ему
$sLogin = (!empty($aFormHandlerResult['data']['login'])) ? htmlspecialchars_decode($aFormHandlerResult['data']['login']) : "";
$sEmail = (!empty($aFormHandlerResult['data']['email'])) ? htmlspecialchars_decode($aFormHandlerResult['data']['email']) : "";
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Личный кабинет пользователя. Авторизация/регистрация. PHP+MySQL+JavaScript,jQuery</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js" integrity="sha384-I7E8VVD/ismYTF4hNIPjVp/Zjvgyol6VFvRkX/vR+Vc4jQkC+hVqc2pM8ODewa9r" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.min.js" integrity="sha384-BBtl+eGJRgqQAUMxJ7pMwbEyER4l1g+O15P+16Ep7Q9Q+zqX6gSbd85u4mG4QzX+" crossorigin="anonymous"></script>
    <script>
        (() => {
            'use strict'
            document.addEventListener('DOMContentLoaded', (event) => {
                // Fetch all the forms we want to apply custom Bootstrap validation styles to
                const forms = document.querySelectorAll('.needs-validation');

                if (forms)
                {
                    // Loop over them and prevent submission
                    Array.from(forms).forEach(form => {
                        form.addEventListener('submit', event => {
                        if (!form.checkValidity()) {
                            event.preventDefault();
                            event.stopPropagation();
                        }

                        form.classList.add('was-validated')
                        }, false);
                    });
                }
            });
        })();
    </script>
</head>
<body>
    <div class="container-md container-fluid">
        <h1 class="my-3">Личный кабинет пользователя</h1>
        <p>
            Сейчас вы <?php echo (checkAuth()) ? "авторизованы" : "не авторизованы";?> на сайте. <br />
            <?php
            if (checkAuth())
            {
                echo "<p>Ваш логин: <strong>" . userData()['login'] . "</strong>.</p>";
                echo "<p>Вы можете <a href='/users.php?action=exit'>выйти</a> из системы.</p>";
            }
            // Если пользователь вышел из системы
            elseif (!empty($_GET['action']))
            {
                if ($_GET['action'] == "exit")
                {
                    echo "Вы успешно вышли из системы";
                }
            }

            // Перенаправим пользователя на главную страницу при успешной авторизации/регистрации
            if (!empty($aFormHandlerResult['success']) && $aFormHandlerResult['success'] === TRUE)
            {
            ?>
                <script>
                    setTimeout(() => {
                        window.location.href="/";
                    }, 3000);
                </script>
            <?php
            }
            ?>
        </p>
        <?php
        // Блок с формами авторизации/регистрации показываем только неавторизованным пользователям
        if (!checkAuth())
        {
        ?>
            <ul class="nav nav-tabs my-3" id="user-action-tabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link <?php print (empty($aFormHandlerResult) || $aFormHandlerResult['type'] == 'auth') ? "active" : "";?>" id="user-auth-tab" data-bs-toggle="tab" data-bs-target="#user-auth-tab-pane" type="button" role="tab" aria-controls="user-auth-tab-pane" aria-selected="true">Авторизация</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link <?php print (!empty($aFormHandlerResult) && $aFormHandlerResult['type'] == 'reg') ? "active" : "";?>" id="user-reg-tab" data-bs-toggle="tab" data-bs-target="#user-reg-tab-pane" type="button" role="tab" aria-controls="user-reg-tab-pane" aria-selected="false">Регистрация</button>
                </li>
            </ul>
            <div class="tab-content bg-light" id="user-action-tabs-content">
                <div class="tab-pane fade px-3 <?php print (empty($aFormHandlerResult) || $aFormHandlerResult['type'] == 'auth') ? "show active" : "";?>" id="user-auth-tab-pane" role="tabpanel" aria-labelledby="user-auth-tab-pane" tabindex="0">
                    <div class="row">
                        <div class="col-xxl-8 col-md-10 rounded text-dark p-3">
                            <!-- Блок для сообщений о результате обработки формы -->
                            <?php
                            // Если была обработана форма
                            if (!empty($aFormHandlerResult) && $aFormHandlerResult['type'] == 'auth')
                            {
                                $sClass = match($aFormHandlerResult['success']) {
                                            TRUE => "my-3 alert alert-success",
                                            FALSE => "my-3 alert alert-danger"
                                };

                                ?>
                                <div class="<?=$sClass?>">
                                    <?=$aFormHandlerResult['message'];?>
                                </div>
                                <?php
                            }
                            ?>
                            <h3 class="my-3">Авторизация пользователя</h3>
                            <form id="form-auth" class="needs-validation" name="form-auth" action="/users.php" method="post" autocomplete="off" novalidate>
                                <div class="my-3">
                                    <label for="auth-login">Логин или электропочта:</label>
                                    <input type="text" id="auth-login" name="login" class="form-control" placeholder="Ваши логин или электропочта" required value="<?php print (empty($aFormHandlerResult) || $aFormHandlerResult['type'] == 'auth') ? $sLogin : "";?>" />
                                    <div class="error invalid-feedback" id="auth-login_error"></div>
                                    <div class="help form-text" id="auth-login_help">Напишите логин или адрес электропочты, указанные вами при регистрации на сайте</div>
                                </div>
                                <div class="my-3">
                                    <label for="auth-password">Пароль:</label>
                                    <input type="password" id="auth-password" name="password" class="form-control" placeholder="Напишите ваш пароль" required />
                                    <div class="error invalid-feedback" id="auth-password_error"></div>
                                    <div class="help form-text" id="auth-password_help">Напишите пароль, указанный вами при регистрации на сайте</div>
                                </div>
                                <div class="my-3">
                                    <input type="submit" class="btn btn-primary" id="auth-submit" name="sign-in" value="Войти" />
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
                <div class="tab-pane fade px-3 <?php print (!empty($aFormHandlerResult) && $aFormHandlerResult['type'] == 'reg') ? "show active" : "";?>" id="user-reg-tab-pane" role="tabpanel" aria-labelledby="user-reg-tab-pane" tabindex="0">
                    <div class="row">
                        <div class="col-xxl-8 col-md-10 rounded text-dark p-3">
                            <!-- Блок для сообщений о результате обработки формы -->
                            <?php
                            // Если была обработана форма
                            if (!empty($aFormHandlerResult) && $aFormHandlerResult['type'] == 'reg')
                            {
                                $sClass = match($aFormHandlerResult['success']) {
                                            TRUE => "my-3 alert alert-success",
                                            FALSE => "my-3 alert alert-danger"
                                };
                               
                                ?>
                                <div class="<?=$sClass?>">
                                    <?=$aFormHandlerResult['message'];?>
                                </div>
                                <?php
                            }
                            ?>
                            <h3 class="my-3">Регистрация пользователя</h3>
                            <form id="form-reg" class="needs-validation" name="form-reg" action="/users.php" method="post" autocomplete="off" novalidate>
                                <div class="row gy-2 mb-3">
                                    <div class="col-md">
                                        <label for="reg-login">Логин:</label>
                                        <input type="text" id="reg-login" name="login" class="form-control" placeholder="Ваш логин для регистрации" required value="<?php print (!empty($aFormHandlerResult) && $aFormHandlerResult['type'] == 'reg') ? $sLogin : "";?>" />
                                        <div class="error invalid-feedback" id="reg-login_error">Логин введен неверно</div>
                                        <div class="help form-text" id="reg-login_help">Напишите логин для регистрации на сайте</div>
                                    </div>
                                    <div class="col-md">
                                        <label for="reg-email">Электропочта:</label>
                                        <input type="email" id="reg-email" name="email" class="form-control" placeholder="Ваш адрес электропочты" required value="<?php print (!empty($aFormHandlerResult) && $aFormHandlerResult['type'] == 'reg') ? $sEmail : "";?>" />
                                        <div class="error invalid-feedback" id="reg-email_error"></div>
                                        <div class="help form-text" id="reg-email_help">Напишите ваш действующий адрес электропочты для регистрации на сайте</div>
                                    </div>
                                </div>
                                <div class="row gy-2 mb-3">
                                    <div class="col-md">
                                        <label for="reg-password">Пароль:</label>
                                        <input type="password" id="reg-password" name="password" class="form-control" placeholder="Напишите ваш пароль" required />
                                        <div class="error invalid-feedback" id="reg-password_error"></div>
                                        <div class="help form-text" id="reg-password_help">Напишите пароль, для регистрации на сайте</div>
                                    </div>
                                    <div class="col-md">
                                        <label for="reg-password2">Подтверждение пароля:</label>
                                        <input type="password" id="reg-password2" name="password2" class="form-control" placeholder="Повторите ваш пароль" required />
                                        <div class="error invalid-feedback" id="reg-password2_error"></div>
                                        <div class="help form-text" id="reg-password2_help">Повторите пароль для его подтверждения и исключения ошибки</div>
                                    </div>
                                </div>
                                <div class="my-3 d-flex">
                                    <input type="submit" class="btn btn-success me-3" id="reg-submit" name="sign-up" value="Зарегистрироваться" />
                                    <input type="reset" class="btn btn-danger" id="reg-reset" name="reset" value="Очистить" />
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php
        }
        ?>  
    </div>
</body>
</html>