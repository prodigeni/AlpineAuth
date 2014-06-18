<?php
//setup database connections using desired settings
require_once __DIR__.'/../helpers/database/autoload.php';  
 
use Illuminate\Database\Capsule\Manager as Capsule;  
 
$capsule = new Capsule; 
 
//settings for database connection
$capsule->addConnection(array(
    'driver'    => DB_DRIVER,
    'host'      => DB_HOST,
    'database'  => DB_DATABASE,
    'username'  => DB_USERNAME,
    'password'  => DB_PASSWORD,
    'charset'   => DB_CHARSET,
    'collation' => DB_COLLATION,
    'prefix'    => DB_PREFIX
));
 
//load Eloquent ORM
$capsule->bootEloquent();

?>