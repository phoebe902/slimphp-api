<?php
require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../config.php';

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

$app = AppFactory::create();
$app->addBodyParsingMiddleware();

// -------------------- AUTH --------------------
// Register
$app->post('/api/register', function(Request $request, Response $response) use ($pdo){
    $data = $request->getParsedBody();
    $password = password_hash($data['password'], PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$data['username'], $password]);
    $response->getBody()->write(json_encode(['message'=>'User registered']));
    return $response->withHeader('Content-Type','application/json');
});

// Login
$app->post('/api/login', function(Request $request, Response $response) use ($pdo){
    $data = $request->getParsedBody();
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username=?");
    $stmt->execute([$data['username']]);
    $user = $stmt->fetch();
    if($user && password_verify($data['password'], $user['password'])){
        $token = bin2hex(random_bytes(16));
        $pdo->prepare("UPDATE users SET token=? WHERE id=?")->execute([$token, $user['id']]);
        $response->getBody()->write(json_encode(['token'=>$token]));
    } else {
        $response->getBody()->write(json_encode(['error'=>'Invalid credentials']));
    }
    return $response->withHeader('Content-Type','application/json');
});

// Logout
$app->post('/api/logout', function(Request $request, Response $response) use ($pdo){
    $data = $request->getParsedBody();
    $stmt = $pdo->prepare("UPDATE users SET token=NULL WHERE token=?");
    $stmt->execute([$data['token']]);
    $response->getBody()->write(json_encode(['message'=>'Logged out']));
    return $response->withHeader('Content-Type','application/json');
});

// -------------------- MOVIE CRUD --------------------
$authMiddleware = function(Request $request, $handler) use ($pdo){
	  $authHeader = $request->getHeaderLine('Authorization');
     if (preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
        $token = $matches[1];
    } else {
        $token = $authHeader; // fallback if no Bearer
    }

    $stmt = $pdo->prepare("SELECT * FROM users WHERE token=?");
    $stmt->execute([$token]);
    $user = $stmt->fetch();

    if(!$user){
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write(json_encode(['error'=>'Unauthorized']));
        return $response->withHeader('Content-Type','application/json')->withStatus(401);
    }

    // attach user info to request
    $request = $request->withAttribute('user', $user);
    return $handler->handle($request);
};

$app->group('/api/movie', function($group) use ($pdo){
    
    // Create movie
    $group->post('', function(Request $request, Response $response){
        global $pdo;
        $data = $request->getParsedBody();
        $stmt = $pdo->prepare("INSERT INTO movie (title, genre) VALUES (?, ?)");
        $stmt->execute([$data['title'], $data['genre']]);
        $response->getBody()->write(json_encode(['message'=>'Movie created']));
        return $response->withHeader('Content-Type','application/json');
    });

    // Get all movies
    $group->get('', function(Request $request, Response $response){
        global $pdo;
        $stmt = $pdo->query("SELECT * FROM movie");
        $movies = $stmt->fetchAll();
        $response->getBody()->write(json_encode($movies));
        return $response->withHeader('Content-Type','application/json');
    });

    // Get movie by ID
    $group->get('/{id}', function(Request $request, Response $response, $args){
        global $pdo;
        $stmt = $pdo->prepare("SELECT * FROM movie WHERE id=?");
        $stmt->execute([$args['id']]);
        $movie = $stmt->fetch();
        $response->getBody()->write(json_encode($movie));
        return $response->withHeader('Content-Type','application/json');
    });

    // Update movie
    $group->put('', function(Request $request, Response $response){
        global $pdo;
        $data = $request->getParsedBody();
        $stmt = $pdo->prepare("UPDATE movie SET title=?, genre=? WHERE id=?");
        $stmt->execute([$data['title'], $data['genre'], $data['id']]);
        $response->getBody()->write(json_encode(['message'=>'Movie updated']));
        return $response->withHeader('Content-Type','application/json');
    });

    // Delete movie
    $group->delete('', function(Request $request, Response $response){
        global $pdo;
        $data = $request->getParsedBody();
        $stmt = $pdo->prepare("DELETE FROM movie WHERE id=?");
        $stmt->execute([$data['id']]);
        $response->getBody()->write(json_encode(['message'=>'Movie deleted']));
        return $response->withHeader('Content-Type','application/json');
    });

})->add($authMiddleware);

$app->run();