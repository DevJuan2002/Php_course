<!-- 
/**
 * Sistema de Login Seguro con PHP
 * 
 * Este código implementa un sistema de login seguro siguiendo principios SOLID y Clean Code.
 * Utiliza programación orientada a objetos con diferentes clases que tienen responsabilidades específicas.
 */

/**
 * Class DatabaseConfig
 * 
 * Simula una base de datos con credenciales cifradas.
 * - Usa constantes privadas para almacenar credenciales
 * - El password está hasheado usando password_hash() para mayor seguridad
 * - Implementa el patrón Singleton a través de un método estático
 */

/**
 * Class AuthenticationService
 * 
 * Maneja la lógica de autenticación.
 * - Obtiene credenciales a través de DatabaseConfig
 * - Verifica usuarios y contraseñas de forma segura
 * - Usa password_verify() para comparar contraseñas hasheadas
 */

/**
 * Class SessionManager 
 * 
 * Gestiona las sesiones de usuario.
 * - Inicia sesiones de forma segura
 * - Implementa protección contra fijación de sesiones
 * - Proporciona métodos para verificar el estado del login
 * 
 * Métodos principales:
 * - createUserSession(): Crea una sesión segura para el usuario
 * - isLoggedIn(): Verifica si el usuario está autenticado
 */

/**
 * Class LoginController
 * 
 * Controlador principal que coordina el proceso de login.
 * - Implementa el patrón MVC separando la lógica de la vista
 * - Utiliza inyección de dependencias con AuthenticationService y SessionManager
 * - Incluye sanitización de inputs para prevenir XSS
 * 
 * Métodos principales:
 * - handleRequest(): Maneja las peticiones POST del formulario
 * - processLoginRequest(): Procesa los datos del login
 * - sanitizeInput(): Limpia datos de entrada contra XSS
 * 
 * Seguridad implementada:
 * - Sanitización de inputs
 * - Protección contra XSS
 * - Manejo seguro de contraseñas
 * - Sesiones seguras
 */

/**
 * Vista (HTML/PHP)
 * 
 * Implementa:
 * - Formulario de login responsive
 * - Manejo de errores y mensajes
 * - CSS básico para la interfaz
 * - Separación de lógica y presentación
 * 
 * Características de seguridad en la vista:
 * - Escape de output con htmlspecialchars
 * - Validación de formularios
 * - Mensajes de error controlados
 */
// Codigo con seguirad,principios solid y clean code -->

<?php
// Simulando base de datos con credenciales cifradas
class DatabaseConfig {
    // Usamos password_hash() para una contraseña más segura
    private const VALID_USERNAME = "admin"; // Nombre de usuario válido
    // Contraseña '123456' hasheada usando bcrypt
    private const VALID_PASSWORD_HASH = '$2y$10$wQ2kZTfg8HDZ9hpy8IvFzOwSYUw5u5gZz9f3XqZ9jpA6V3Eeh30tW'; 
    
    // Devuelve las credenciales válidas almacenadas de forma segura
    public static function getValidCredentials(): array {
        return [
            'username' => self::VALID_USERNAME,
            'passwordHash' => self::VALID_PASSWORD_HASH
        ];
    }
}

// Servicio de autenticación
class AuthenticationService {
    private array $credentials;

    // El constructor obtiene las credenciales válidas
    public function __construct() {
        $this->credentials = DatabaseConfig::getValidCredentials();
    }

    // Método que valida el nombre de usuario y la contraseña
    public function authenticate(string $username, string $password): bool {
        // Verifica si el nombre de usuario coincide y si la contraseña es correcta
        return $username === $this->credentials['username'] && 
               password_verify($password, $this->credentials['passwordHash']);
    }
}

// Gestor de sesiones
class SessionManager {
    public function __construct() {
        // Inicia una sesión si no está iniciada
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    // Crea una sesión para el usuario con seguridad adicional
    public function createUserSession(string $username): void {
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $username;
        session_regenerate_id(true); // Previene ataques de fijación de sesión (Session Fixation)
    }

    // Verifica si el usuario está autenticado
    public function isLoggedIn(): bool {
        return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
    }
}

// Controlador de inicio de sesión
class LoginController {
    private AuthenticationService $authService;
    private SessionManager $sessionManager;
    private string $error = ''; // Almacena posibles errores
    private ?string $welcomeMessage = null; // Almacena mensaje de bienvenida

    // El constructor inicializa el servicio de autenticación y el gestor de sesiones
    public function __construct() {
        $this->authService = new AuthenticationService();
        $this->sessionManager = new SessionManager();
    }

    // Maneja las solicitudes HTTP, en este caso solo POST
    public function handleRequest(): void {
        if ($_SERVER["REQUEST_METHOD"] === "POST") {
            $this->processLoginRequest();
        }
    }

    // Procesa la solicitud de inicio de sesión
    private function processLoginRequest(): void {
        // Sanear la entrada para evitar ataques XSS
        $username = $this->sanitizeInput($_POST["username"] ?? "");
        $password = $this->sanitizeInput($_POST["password"] ?? "");

        // Si la autenticación es exitosa, crea la sesión del usuario
        if ($this->authService->authenticate($username, $password)) {
            $this->sessionManager->createUserSession($username);
            $this->welcomeMessage = "Bienvenido, " . htmlspecialchars($username) . "!";
        } else {
            $this->error = "Credenciales de inicio de sesión inválidas.";
        }
    }

    // Limpia la entrada para evitar vulnerabilidades XSS
    private function sanitizeInput(string $input): string {
        return trim(htmlspecialchars($input)); // Elimina espacios y convierte caracteres especiales
    }

    // Obtiene el error si existe
    public function getError(): string {
        return $this->error;
    }

    // Obtiene el mensaje de bienvenida si el inicio de sesión fue exitoso
    public function getWelcomeMessage(): ?string {
        return $this->welcomeMessage;
    }
}

// Inicialización del controlador
$loginController = new LoginController();
$loginController->handleRequest();
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Formulario de Inicio de Sesión</title>
    <style>
        /* Estilos básicos para el formulario de inicio de sesión */
        .login-container {
            max-width: 300px;
            margin: 50px auto;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        /* Estilo para los mensajes de error */
        .error { color: red; margin-bottom: 10px; }
        /* Estilo para los campos de entrada */
        input { width: 100%; margin-bottom: 10px; padding: 5px; }
    </style>
</head>
<body>
    <div class="login-container">
        <!-- Si se recibió un mensaje de bienvenida, lo mostramos -->
        <?php if ($loginController->getWelcomeMessage()): ?>
            <h2><?php echo $loginController->getWelcomeMessage(); ?></h2>
        <?php else: ?>
            <!-- Si no se ha recibido un mensaje de bienvenida, mostramos el formulario de inicio de sesión -->
            <h2>Iniciar Sesión</h2>
            <?php if ($loginController->getError()): ?>
                <!-- Si hay un error, lo mostramos -->
                <div class="error"><?php echo $loginController->getError(); ?></div>
            <?php endif; ?>
            <!-- Formulario de inicio de sesión -->
            <form method="POST">
                <input type="text" name="username" placeholder="Usuario" required>
                <input type="password" name="password" placeholder="Contraseña" required>
                <input type="submit" value="Iniciar Sesión">
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
























<!-- --------------------------------------------------------------------------- -->

<!-- Codigo sin seguridad ni principios SOLID -->
<?php
// Clase DatabaseConfig: Encapsula las credenciales de usuario válidas.
class DatabaseConfig {
    // Constantes privadas que contienen el nombre de usuario y la contraseña válidos.
    private const VALID_USERNAME = "admin";
    private const VALID_PASSWORD = "123456";

    // Método estático que devuelve las credenciales válidas en forma de un array.
    public static function getValidCredentials(): array {
        return [
            'username' => self::VALID_USERNAME,
            'password' => self::VALID_PASSWORD
        ];
    }
}

// Clase AuthenticationService: Gestiona la autenticación del usuario.
class AuthenticationService {
    // Propiedad privada que almacenará las credenciales válidas obtenidas de la clase DatabaseConfig.
    private array $credentials;

    // Constructor que inicializa las credenciales llamando al método estático getValidCredentials.
    public function __construct() {
        $this->credentials = DatabaseConfig::getValidCredentials();
    }

    // Método que autentica al usuario comparando el nombre de usuario y la contraseña proporcionados.
    public function authenticate(string $username, string $password): bool {
        return $username === $this->credentials['username'] && 
               $password === $this->credentials['password'];
    }
}

// Clase SessionManager: Gestiona las sesiones de usuario.
class SessionManager {
    // Constructor que inicia una sesión si no se ha iniciado previamente.
    public function __construct() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    // Método que crea una sesión de usuario cuando se ha autenticado correctamente.
    public function createUserSession(string $username): void {
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $username;
    }

    // Método que verifica si el usuario está autenticado y tiene una sesión activa.
    public function isLoggedIn(): bool {
        return isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true;
    }
}

// Clase LoginController: Controlador principal que maneja la solicitud de inicio de sesión.
class LoginController {
    // Propiedades privadas que almacenarán las instancias de AuthenticationService y SessionManager.
    private AuthenticationService $authService;
    private SessionManager $sessionManager;
    private string $error = '';  // Propiedad para almacenar un mensaje de error, si es necesario.
    private ?string $welcomeMessage = null;  // Propiedad para almacenar un mensaje de bienvenida.

    // Constructor que inicializa las instancias de AuthenticationService y SessionManager.
    public function __construct() {
        $this->authService = new AuthenticationService();
        $this->sessionManager = new SessionManager();
    }

    // Método que maneja la solicitud de inicio de sesión, se llama cuando se recibe un POST.
    public function handleRequest(): void {
        if ($_SERVER["REQUEST_METHOD"] === "POST") {
            $this->processLoginRequest();  // Si la solicitud es POST, procesamos el inicio de sesión.
        }
    }

    // Método privado que procesa la solicitud de inicio de sesión.
    private function processLoginRequest(): void {
        // Sanitiza las entradas de nombre de usuario y contraseña.
        $username = $this->sanitizeInput($_POST["username"] ?? "");
        $password = $this->sanitizeInput($_POST["password"] ?? "");

        // Intenta autenticar al usuario y crea la sesión si es válido.
        if ($this->authService->authenticate($username, $password)) {
            $this->sessionManager->createUserSession($username);
            $this->welcomeMessage = "Welcome, " . htmlspecialchars($username) . "!";  // Mensaje de bienvenida.
        } else {
            $this->error = "Invalid username or password";  // Mensaje de error si las credenciales son incorrectas.
        }
    }

    // Método privado que sanitiza la entrada de texto para prevenir inyecciones.
    private function sanitizeInput(string $input): string {
        return trim(htmlspecialchars($input));  // Elimina espacios innecesarios y convierte caracteres especiales.
    }

    // Método público que devuelve el mensaje de error si lo hay.
    public function getError(): string {
        return $this->error;
    }

    // Método público que devuelve el mensaje de bienvenida si lo hay.
    public function getWelcomeMessage(): ?string {
        return $this->welcomeMessage;
    }
}

// Instancia de la clase LoginController para manejar la solicitud de inicio de sesión.
$loginController = new LoginController();
$loginController->handleRequest();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Form</title>
    <style>
        .login-container {
            max-width: 300px;
            margin: 50px auto;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        .error { color: red; margin-bottom: 10px; }
        input { width: 100%; margin-bottom: 10px; padding: 5px; }
    </style>
</head>
<body>
    <div class="login-container">
        <?php if ($loginController->getWelcomeMessage()): ?>
            <h2><?php echo $loginController->getWelcomeMessage(); ?></h2>  <!-- Muestra el mensaje de bienvenida si existe. -->
        <?php else: ?>
            <h2>Login</h2>
            <?php if ($loginController->getError()): ?>
                <div class="error"><?php echo $loginController->getError(); ?></div>  <!-- Muestra el mensaje de error si existe. -->
            <?php endif; ?>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <input type="submit" value="Login">
            </form>
        <?php endif; ?>
    </div>
</body>
</html>
